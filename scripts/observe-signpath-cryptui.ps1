# LOCAL-182 only: read-only observations of the verifier process, not a signing step.
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [int] $TargetProcessId,
    [Parameter(Mandatory)] [long] $TargetStartTicks,
    [Parameter(Mandatory)] [string] $EvidenceDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$boundaryPath = Join-Path $EvidenceDirectory 'cryptui-native-boundary.jsonl'
$outputPath = Join-Path $EvidenceDirectory 'cryptui-observer.jsonl'
$readyPath = Join-Path $EvidenceDirectory 'cryptui-observer.ready'

function Write-Observation([Collections.IDictionary] $Record) {
    $Record['utc'] = [DateTime]::UtcNow.ToString('o')
    $Record['target_pid'] = $TargetProcessId
    $Record['target_start_utc_ticks'] = $TargetStartTicks
    $Record['observer_pid'] = $PID
    $line = ConvertTo-Json -InputObject $Record -Depth 8 -Compress
    [IO.File]::AppendAllText($outputPath, "$line`n")
    Write-Host "[LOCAL-182 observer] $line"
}

$target = $null
try {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class Local182WindowSnapshot
{
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool WindowCallback(IntPtr window, IntPtr parameter);
    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumThreadWindows(uint thread, WindowCallback callback, IntPtr parameter);
    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetWindowTextW(IntPtr window, StringBuilder text, int count);
    [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetClassNameW(IntPtr window, StringBuilder text, int count);
    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern IntPtr GetWindow(IntPtr window, uint command);

    public sealed class Window
    {
        public string hwnd, owner, caption, window_class;
        public bool visible;
        public int caption_error, class_error;
    }
    public sealed class Result
    {
        // FALSE can also mean no windows; it is not by itself an error.
        public bool enum_return;
        public int skipped_changed;
        public List<Window> windows = new List<Window>();
    }
    public static Result Read(uint processId, uint threadId)
    {
        var result = new Result();
        result.enum_return = EnumThreadWindows(threadId, (window, parameter) => {
            uint ownerPid;
            if (GetWindowThreadProcessId(window, out ownerPid) != threadId || ownerPid != processId) {
                result.skipped_changed++;
                return true;
            }
            // Only external-process nonchild captions. No WM_GETTEXT or child controls.
            var caption = new StringBuilder(257);
            int captionLength = GetWindowTextW(window, caption, caption.Capacity);
            int captionError = Marshal.GetLastWin32Error();
            var windowClass = new StringBuilder(257);
            int classLength = GetClassNameW(window, windowClass, windowClass.Capacity);
            int classError = Marshal.GetLastWin32Error();
            var item = new Window {
                hwnd = "0x" + window.ToInt64().ToString("X"),
                owner = "0x" + GetWindow(window, 4).ToInt64().ToString("X"), // GW_OWNER; no traversal.
                caption = caption.ToString(), window_class = windowClass.ToString(),
                visible = IsWindowVisible(window),
                caption_error = captionLength == 0 ? captionError : 0,
                class_error = classLength == 0 ? classError : 0
            };
            if (GetWindowThreadProcessId(window, out ownerPid) == threadId && ownerPid == processId) {
                result.windows.Add(item);
            } else {
                result.skipped_changed++;
            }
            return true;
        }, IntPtr.Zero);
        return result;
    }
}
'@
    $target = [Diagnostics.Process]::GetProcessById($TargetProcessId)
    if ($TargetProcessId -eq $PID -or $target.HasExited -or
        $target.StartTime.ToUniversalTime().Ticks -ne $TargetStartTicks) {
        throw 'Observer target identity does not match the verifier.'
    }
    Write-Observation @{ phase = 'OBSERVER_READY'; process_start_utc = $target.StartTime.ToUniversalTime().ToString('o') }
    [IO.File]::WriteAllText($readyPath, 'ready')
    $waiting = [Diagnostics.Stopwatch]::StartNew()
    $entry = $null
    $sampleIndex = 0
    $sampleSeconds = @(2, 30, 120)
    $reason = 'samples_complete'
    while ($sampleIndex -lt $sampleSeconds.Count) {
        $target.Refresh()
        if ($target.HasExited -or $target.StartTime.ToUniversalTime().Ticks -ne $TargetStartTicks) {
            $reason = 'target_exited_or_changed'
            break
        }
        $returned = $false
        if ([IO.File]::Exists($boundaryPath)) {
            # Share with the appending verifier; parse only newline-terminated records.
            $stream = [IO.File]::Open($boundaryPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            $reader = [IO.StreamReader]::new($stream)
            try { $text = $reader.ReadToEnd() }
            finally { $reader.Dispose() }
            $lastNewline = $text.LastIndexOf("`n")
            if ($lastNewline -ge 0) {
                foreach ($line in $text.Substring(0, $lastNewline).Split("`n")) {
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    $record = ConvertFrom-Json -InputObject $line -AsHashtable
                    if ($record.pid -ne $TargetProcessId -or $record.process_start_utc_ticks -ne $TargetStartTicks) { continue }
                    if ($record.phase -eq 'NATIVE_ENTER') { $entry = $record }
                    if ($record.phase -eq 'NATIVE_RETURN') { $returned = $true }
                }
            }
        }
        if ($returned) { $reason = 'native_return_observed'; break }
        if ($null -eq $entry) {
            # Only the observer expires; never interrupt the verifier if entry is absent.
            if ($waiting.Elapsed.TotalSeconds -ge 30) { $reason = 'native_entry_not_observed'; break }
        }
        else {
            $elapsed = ([DateTime]::UtcNow.Ticks - [long]$entry.utc_ticks) / [TimeSpan]::TicksPerSecond
            if ($elapsed -ge $sampleSeconds[$sampleIndex]) {
                $sampleStart = [DateTime]::UtcNow.ToString('o')
                Write-Observation @{ phase = 'SNAPSHOT_BEGIN'; requested_seconds = $sampleSeconds[$sampleIndex]; elapsed_seconds = $elapsed; native_tid = $entry.native_tid }
                $rows = @(foreach ($thread in $target.Threads) {
                    $row = [ordered]@{ tid = $thread.Id; is_import_thread = ($thread.Id -eq $entry.native_tid); state = $null; wait_reason = $null; window_scan = $null }
                    try {
                        $state = $thread.ThreadState
                        $row.state = [string]$state
                        if ($state -eq [Diagnostics.ThreadState]::Wait) { $row.wait_reason = [string]$thread.WaitReason }
                    }
                    catch {
                        $row['state_error_type'] = $_.Exception.GetType().FullName
                        $row['state_error_hresult'] = $_.Exception.HResult
                    }
                    try { $row.window_scan = [Local182WindowSnapshot]::Read([uint32]$TargetProcessId, [uint32]$thread.Id) }
                    catch {
                        $row['window_error_type'] = $_.Exception.GetType().FullName
                        $row['window_error_hresult'] = $_.Exception.HResult
                    }
                    $thread.Dispose()
                    $row
                })
                if ($target.HasExited) { $reason = 'target_exited_during_snapshot'; break }
                Write-Observation @{
                    phase = 'SNAPSHOT'; requested_seconds = $sampleSeconds[$sampleIndex]; elapsed_seconds = $elapsed
                    sample_start_utc = $sampleStart; native_tid = $entry.native_tid; threads = $rows
                }
                $sampleIndex++
            }
        }
        Start-Sleep -Milliseconds 100
    }
    Write-Observation @{ phase = 'OBSERVER_DONE'; reason = $reason; snapshots = $sampleIndex }
}
catch {
    Write-Observation @{ phase = 'OBSERVER_ERROR'; error_type = $_.Exception.GetType().FullName; hresult = $_.Exception.HResult }
}
finally {
    if ($null -ne $target) { $target.Dispose() }
}
