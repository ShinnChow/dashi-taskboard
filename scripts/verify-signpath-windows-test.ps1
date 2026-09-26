# Only for this workflow's disposable GitHub-hosted Windows runner.
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ArtifactDirectory,
    [Parameter(Mandatory)] [string] $EvidenceDirectory,
    [Parameter(Mandatory)]
    [ValidatePattern('\A[0-9A-Fa-f]{64}\z')]
    [string] $ExpectedSignerSha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Temporary certificate trust is allowed only on this disposable GitHub-hosted Windows runner. Do not run on a workstation or self-hosted runner.'
}

$names = @('codex-taskboard-launcher.exe', 'codex-taskboard-test-setup.exe')
$entries = @(Get-ChildItem -LiteralPath $ArtifactDirectory -Force)
if ($entries.Count -ne 2 -or @($entries | Where-Object { $_.PSIsContainer }).Count -ne 0 -or
    @(Compare-Object -ReferenceObject $names -DifferenceObject @($entries.Name) -CaseSensitive).Count -ne 0) {
    throw 'Signed artifact must contain exactly the two expected PE files at its root.'
}

# The Windows SDK is included in windows-2025. Use the latest installed x64 tool.
$sdkBin = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/bin'
$signTool = Get-ChildItem -Path "$sdkBin/*/x64/signtool.exe" -File |
    Sort-Object { [version]$_.Directory.Parent.Name } -Descending |
    Select-Object -First 1
if ($null -eq $signTool) { throw 'Windows SDK x64 signtool.exe was not found.' }

New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
$records = @()
$testCertificate = $null
foreach ($name in $names) {
    $path = Join-Path $ArtifactDirectory $name
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($null -eq $signature.SignerCertificate) { throw "No signer certificate on ${name}." }
    $certificate = $signature.SignerCertificate
    $fingerprint = $certificate.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256)
    if ($fingerprint -ne $ExpectedSignerSha256) { throw "Unexpected signer on ${name}: $fingerprint" }
    if ($signature.SignatureType -ne 'Authenticode') { throw "Expected an embedded Authenticode signature on ${name}." }
    $testCertificate = $certificate
    $records += [ordered]@{
        artifact_path = $name
        file_sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        signer_sha256 = $fingerprint
        signer_subject = $certificate.Subject
        signer_issuer = $certificate.Issuer
        signer_serial_number = $certificate.SerialNumber
        signer_not_before_utc = $certificate.NotBefore.ToUniversalTime().ToString('o')
        signer_not_after_utc = $certificate.NotAfter.ToUniversalTime().ToString('o')
        status_before_temporary_trust = [string]$signature.Status
        status_message_before_temporary_trust = $signature.StatusMessage
        status_after_temporary_trust = $null
        signtool_exit_code = $null
    }
}

# Fingerprint equality identifies the independently approved public certificate;
# it is NOT proof that the PE signature or file digest is valid.
$certificatePath = Join-Path $EvidenceDirectory 'test-signer.cer'
[IO.File]::WriteAllBytes($certificatePath, $testCertificate.RawData)
$storePath = "Cert:\CurrentUser\Root\$($testCertificate.Thumbprint)"
$diagnosticPath = Join-Path $EvidenceDirectory 'verification-boundaries.log'
$marker = '{0} BEFORE Test-Path pre-import store={1}' -f [DateTime]::UtcNow.ToString('o'), $storePath
[IO.File]::AppendAllText($diagnosticPath, "$marker`n")
Write-Host $marker
$addedTrust = -not (Test-Path -LiteralPath $storePath)
$marker = '{0} AFTER Test-Path pre-import addedTrust={1}' -f [DateTime]::UtcNow.ToString('o'), $addedTrust
[IO.File]::AppendAllText($diagnosticPath, "$marker`n")
Write-Host $marker
$verified = $false
try {
    if ($addedTrust) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public static class Local182CryptUI
{
    // x64: offsets 0, 4, 8, 16, 24; size 32. The union is one pointer.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 8)]
    private struct CRYPTUI_WIZ_IMPORT_SRC_INFO
    {
        public uint dwSize;
        public uint dwSubjectChoice;
        public IntPtr pCertContext;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.LPWStr)] public string pwszPassword;
    }

    [DllImport("crypt32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CertOpenStore(IntPtr provider, uint encoding,
        IntPtr cryptProvider, uint flags, string storeName);

    [DllImport("cryptui.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUIWizImport(uint flags, IntPtr parent, string title,
        [In] ref CRYPTUI_WIZ_IMPORT_SRC_INFO source, IntPtr destination);

    [DllImport("crypt32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertCloseStore(IntPtr store, uint flags);

    // Capture each cached Win32 error before returning to PowerShell.
    public static IntPtr OpenRoot(out int error)
    {
        // CERT_STORE_PROV_SYSTEM_W; CURRENT_USER | OPEN_EXISTING.
        IntPtr store = CertOpenStore(new IntPtr(10), 0, IntPtr.Zero, 0x00014000, "Root");
        error = Marshal.GetLastWin32Error();
        return store;
    }

    public static bool ImportCertificate(IntPtr store, X509Certificate2 certificate, out int error)
    {
        var source = new CRYPTUI_WIZ_IMPORT_SRC_INFO {
            dwSize = (uint)Marshal.SizeOf<CRYPTUI_WIZ_IMPORT_SRC_INFO>(),
            dwSubjectChoice = 2, // CRYPTUI_WIZ_IMPORT_SUBJECT_CERT_CONTEXT
            pCertContext = certificate.Handle,
            dwFlags = 0,
            pwszPassword = string.Empty
        };
        try {
            // CRYPTUI_WIZ_NO_UI | CRYPTUI_WIZ_IMPORT_ALLOW_CERT.
            bool imported = CryptUIWizImport(0x00020001, IntPtr.Zero, null, ref source, store);
            error = Marshal.GetLastWin32Error();
            return imported;
        }
        finally {
            GC.KeepAlive(certificate); // The borrowed PCCERT_CONTEXT belongs to this object.
        }
    }

    public static bool CloseRoot(IntPtr store, out int error)
    {
        bool closed = CertCloseStore(store, 0);
        error = Marshal.GetLastWin32Error();
        return closed;
    }
}
'@
        $rootStore = [IntPtr]::Zero
        [int]$openError = 0
        [int]$importError = 0
        [int]$closeError = 0
        try {
            $marker = '{0} BEFORE CertOpenStore CurrentUser/Root flags=0x00014000' -f [DateTime]::UtcNow.ToString('o')
            [IO.File]::AppendAllText($diagnosticPath, "$marker`n")
            Write-Host $marker
            $rootStore = [Local182CryptUI]::OpenRoot([ref]$openError)
            $marker = '{0} AFTER CertOpenStore success={1} win32={2}' -f [DateTime]::UtcNow.ToString('o'), ($rootStore -ne [IntPtr]::Zero), $openError
            [IO.File]::AppendAllText($diagnosticPath, "$marker`n")
            Write-Host $marker
            if ($rootStore -eq [IntPtr]::Zero) {
                throw "CertOpenStore CurrentUser/Root failed with Win32 error $openError."
            }
            $marker = '{0} BEFORE CryptUIWizImport CurrentUser/Root flags=0x00020001 (NO_UI)' -f [DateTime]::UtcNow.ToString('o')
            [IO.File]::AppendAllText($diagnosticPath, "$marker`n")
            Write-Host $marker
            $imported = [Local182CryptUI]::ImportCertificate($rootStore, $testCertificate, [ref]$importError)
            $marker = '{0} AFTER CryptUIWizImport success={1} win32={2}' -f [DateTime]::UtcNow.ToString('o'), $imported, $importError
            [IO.File]::AppendAllText($diagnosticPath, "$marker`n")
            Write-Host $marker
            if (-not $imported) {
                throw "CryptUIWizImport CurrentUser/Root failed with Win32 error $importError."
            }
        }
        finally {
            if ($rootStore -ne [IntPtr]::Zero) {
                try {
                    $marker = '{0} BEFORE CertCloseStore CurrentUser/Root' -f [DateTime]::UtcNow.ToString('o')
                    [IO.File]::AppendAllText($diagnosticPath, "$marker`n")
                    Write-Host $marker
                }
                finally {
                    $closed = [Local182CryptUI]::CloseRoot($rootStore, [ref]$closeError)
                }
                $marker = '{0} AFTER CertCloseStore success={1} win32={2}' -f [DateTime]::UtcNow.ToString('o'), $closed, $closeError
                [IO.File]::AppendAllText($diagnosticPath, "$marker`n")
                Write-Host $marker
                if (-not $closed) {
                    throw "CertCloseStore failed with Win32 error $closeError."
                }
            }
        }
    }
    foreach ($record in $records) {
        $path = Join-Path $ArtifactDirectory $record.artifact_path
        # /pa checks Authenticode rather than driver policy; no /a catalog fallback.
        # /all checks every embedded signature. Any nonzero exit, even a warning, fails.
        $marker = '{0} BEFORE SignTool pipeline file={1} tool={2}' -f [DateTime]::UtcNow.ToString('o'), $record.artifact_path, $signTool.FullName
        [IO.File]::AppendAllText($diagnosticPath, "$marker`n")
        Write-Host $marker
        & $signTool.FullName verify /pa /all /v $path 2>&1 |
            Tee-Object -FilePath (Join-Path $EvidenceDirectory "$($record.artifact_path).signtool.txt")
        $record.signtool_exit_code = $LASTEXITCODE
        $marker = '{0} AFTER SignTool pipeline file={1} exit={2}' -f [DateTime]::UtcNow.ToString('o'), $record.artifact_path, $record.signtool_exit_code
        [IO.File]::AppendAllText($diagnosticPath, "$marker`n")
        Write-Host $marker
        if ($LASTEXITCODE -ne 0) { throw "SignTool integrity/policy verification failed for $($record.artifact_path)." }
        $marker = '{0} BEFORE Get-AuthenticodeSignature post-trust file={1}' -f [DateTime]::UtcNow.ToString('o'), $record.artifact_path
        [IO.File]::AppendAllText($diagnosticPath, "$marker`n")
        Write-Host $marker
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        $marker = '{0} AFTER Get-AuthenticodeSignature post-trust file={1} status={2}' -f [DateTime]::UtcNow.ToString('o'), $record.artifact_path, $signature.Status
        [IO.File]::AppendAllText($diagnosticPath, "$marker`n")
        Write-Host $marker
        $record.status_after_temporary_trust = [string]$signature.Status
        if ($signature.Status -ne 'Valid' -or $signature.SignatureType -ne 'Authenticode' -or
            $null -eq $signature.SignerCertificate -or
            $signature.SignerCertificate.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256) -ne $ExpectedSignerSha256) {
            throw "Signature verification failed for $($record.artifact_path): $($signature.Status) / $($signature.StatusMessage)"
        }
    }
    $verified = $true
}
finally {
    $marker = '{0} BEFORE finally cleanup addedTrust={1}' -f [DateTime]::UtcNow.ToString('o'), $addedTrust
    [IO.File]::AppendAllText($diagnosticPath, "$marker`n")
    Write-Host $marker
    if ($addedTrust -and (Test-Path -LiteralPath $storePath)) {
        $marker = '{0} BEFORE Remove-Item temporary trust' -f [DateTime]::UtcNow.ToString('o')
        [IO.File]::AppendAllText($diagnosticPath, "$marker`n")
        Write-Host $marker
        Remove-Item -LiteralPath $storePath -Force
        $marker = '{0} AFTER Remove-Item temporary trust' -f [DateTime]::UtcNow.ToString('o')
        [IO.File]::AppendAllText($diagnosticPath, "$marker`n")
        Write-Host $marker
    }
    $marker = '{0} AFTER finally cleanup; BEFORE verification-report pipeline' -f [DateTime]::UtcNow.ToString('o')
    [IO.File]::AppendAllText($diagnosticPath, "$marker`n")
    Write-Host $marker
    [ordered]@{
        verified = $verified
        expected_signer_sha256 = $ExpectedSignerSha256.ToUpperInvariant()
        trust_scope = 'Disposable GitHub-hosted runner CurrentUser/Root only; not public trust.'
        temporary_trust_removed = $addedTrust -and -not (Test-Path -LiteralPath $storePath)
        files = $records
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'verification.json') -Encoding utf8
    $marker = '{0} AFTER verification-report pipeline verified={1}' -f [DateTime]::UtcNow.ToString('o'), $verified
    [IO.File]::AppendAllText($diagnosticPath, "$marker`n")
    Write-Host $marker
}
Write-Host 'PASS: both PE signatures are intact and match the pinned test certificate; temporary runner trust has been cleaned up.'
