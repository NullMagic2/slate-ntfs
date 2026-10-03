# Module: capture_chkdsk_reference
# Purpose: Capture read-only Windows checks and binary identities for a fixture.
# Created: 2026-09-30
# Architecture: Runs inside the Windows test VM; a read-only disposable disk supplies
#     the fixture and host tooling collects the transcript.

param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z]:\\$')][string]$VolumeRoot,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$CaseId,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$driveLetter = $VolumeRoot.Substring(0, 1).ToUpperInvariant()
if ($driveLetter -ieq $env:SystemDrive.Substring(0, 1)) {
    throw 'The host system drive is not a disposable fixture.'
}
$volume = Get-Volume -DriveLetter $driveLetter
if ($volume.FileSystem -ne 'NTFS') {
    throw 'The fixture volume must use NTFS.'
}
$partition = Get-Partition -DriveLetter $driveLetter
$disk = Get-Disk -Number $partition.DiskNumber
if (-not $disk.IsReadOnly) {
    throw 'Mount the disposable VM snapshot read-only before running chkdsk.'
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$transcript = Join-Path $OutputDirectory "$CaseId.chkdsk.txt"
# No /F, /R, /B, /spotfix, or other repairing option is passed.
$messages = & chkdsk.exe "$driveLetter`:" 2>&1
$exitCode = $LASTEXITCODE
$messages | Out-File -LiteralPath $transcript -Encoding UTF8
$manifest = [ordered]@{
    case_id = $CaseId
    captured_utc = (Get-Date).ToUniversalTime().ToString('o')
    volume_label = $volume.FileSystemLabel
    volume_read_only = [bool]$disk.IsReadOnly
    command = "chkdsk.exe $driveLetter`:"
    exit_code = $exitCode
    transcript_file = [System.IO.Path]::GetFileName($transcript)
}
$manifestPath = Join-Path $OutputDirectory "$CaseId.chkdsk.json"
$manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Write-Output $manifestPath
