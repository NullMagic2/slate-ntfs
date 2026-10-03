# Module: tests.windows.capture_hibernation_sample
# Purpose: Capture reviewed hibernation fixtures from disposable Windows volumes.
# Created: 2026-10-02
# Architecture: Records guest state and fixture evidence; verify_hibernation_corpus.py validates
# the collected corpus.

param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z]:\\$')][string]$VolumeRoot,
    [Parameter(Mandatory = $true)][ValidateSet('full-shutdown', 'fast-startup', 'hibernated', 'resumed')][string]$State,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$CaseId,
    [Parameter(Mandatory = $true)][ValidateSet('Windows10', 'Windows11')][string]$WindowsRelease,
    [Parameter(Mandatory = $true)][string]$WindowsVersion,
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
    throw 'Mount the disposable VM snapshot read-only before capture.'
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$hiberPath = Join-Path $VolumeRoot 'hiberfil.sys'
$samplePath = Join-Path $OutputDirectory "$CaseId.page.bin"
$present = Test-Path -LiteralPath $hiberPath -PathType Leaf
$digest = $null
if ($present) {
    $page = New-Object byte[] 4096
    $stream = [System.IO.File]::Open($hiberPath, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $read = 0
        while ($read -lt $page.Length) {
            $count = $stream.Read($page, $read, $page.Length - $read)
            if ($count -eq 0) { throw 'hiberfil.sys is shorter than 4096 bytes.' }
            $read += $count
        }
    }
    finally { $stream.Dispose() }
    [System.IO.File]::WriteAllBytes($samplePath, $page)
    $digest = (Get-FileHash -LiteralPath $samplePath -Algorithm SHA256).Hash.ToLowerInvariant()
}

$manifest = [ordered]@{
    origin = 'disposable-windows-vm-snapshot'
    case_id = $CaseId
    expected_transition = $State
    windows_release = $WindowsRelease
    windows_version = $WindowsVersion
    captured_utc = (Get-Date).ToUniversalTime().ToString('o')
    volume_label = $volume.FileSystemLabel
    volume_read_only = [bool]$disk.IsReadOnly
    hibernation_file_present = [bool]$present
    page_file = $(if ($present) { [System.IO.Path]::GetFileName($samplePath) } else { $null })
    page_sha256 = $digest
    classifier_expected = $null
}
$manifestPath = Join-Path $OutputDirectory "$CaseId.json"
$manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Write-Output $manifestPath
