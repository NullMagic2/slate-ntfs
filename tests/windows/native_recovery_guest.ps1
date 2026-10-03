# Module: tests.windows.native_recovery_guest
# Purpose: Capture native recovery evidence for disposable Windows cases.
# Created: 2026-10-02
# Architecture: prepare_native_recovery.py renders this guest template;
# verify_native_recovery.py checks its transcript.

# Render with prepare_native_recovery.py. Run elevated in a disposable VM only.
param([switch]$Shutdown)
$ErrorActionPreference = 'Stop'
$runId = '@RUN_ID@'
$cases = ConvertFrom-Json @'
@CASES_JSON@
'@
Start-Transcript -Path "C:\$runId.txt" -Force
try {
    "RUN_ID=$runId"
    $os = Get-CimInstance Win32_OperatingSystem
    "WINDOWS_BUILD=$($os.BuildNumber)"
    foreach ($case in $cases) {
        $disks = @(Get-Disk | Where-Object { $_.Signature -eq $case.signature })
        if ($disks.Count -ne 1 -or $disks[0].Size -ne 68157440) { throw 'Missing or ambiguous test disk' }
        $parts = @(Get-Partition -DiskNumber $disks[0].Number | Where-Object { $_.Type -eq 'IFS' })
        if ($parts.Count -ne 1) { throw 'Unexpected test partition layout' }
        $part = $parts[0]
        if (!$part.DriveLetter) {
            $part | Add-PartitionAccessPath -AssignDriveLetter
            $part = Get-Partition -DiskNumber $disks[0].Number -PartitionNumber $part.PartitionNumber
        }
        $drive = "$($part.DriveLetter):"
        "CASE_SIGNATURE=$($case.signature);DRIVE=$drive"
        'CONTENT=' + [IO.File]::ReadAllText($drive+'\write.bin')
        & fsutil.exe dirty query $drive
        & chkdsk.exe $drive
        'CHKDSK_EXIT=' + $LASTEXITCODE
    }
    # Read all current-boot NTFS events; a zero chkdsk exit alone is insufficient.
    $events = @(Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$os.LastBootUpTime} |
        Where-Object { $_.ProviderName -eq 'Ntfs' })
    foreach ($event in $events) { 'NTFS_EVENT=' + ($event.ToXml() -replace "`r?`n", ' ') }
    "RUN_COMPLETE=$runId"
} catch { 'RUN_ERROR=' + $_ } finally {
    Stop-Transcript
    if ($Shutdown) { shutdown.exe /s /t 0 }
}
