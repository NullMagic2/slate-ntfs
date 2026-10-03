# Module: tests.windows.run_readonly_chkdsk_vhd
# Purpose: Collect native filesystem checks from a read-only disposable VHD.
# Created: 2026-10-02
# Architecture: Attaches the staged VHD and captures Windows evidence; the host verification
# tools assess that evidence.

param(
    [Parameter(Mandatory = $true)][string]$ImagePath,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$CaseId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script in an elevated PowerShell session.'
}
$resolved = (Resolve-Path -LiteralPath $ImagePath).Path
if ([System.IO.Path]::GetExtension($resolved) -ine '.vhd') {
    throw 'Only a disposable fixed .vhd fixture is accepted.'
}
$stream = [System.IO.File]::OpenRead($resolved)
try {
    if ($stream.Length -lt 33MB) { throw 'VHD fixture is too small.' }
    $stream.Seek(-512, [System.IO.SeekOrigin]::End) | Out-Null
    $footer = New-Object byte[] 512
    if ($stream.Read($footer, 0, 512) -ne 512 -or
        [System.Text.Encoding]::ASCII.GetString($footer, 0, 8) -ne 'conectix') {
        throw 'Missing fixed VHD footer.'
    }
}
finally { $stream.Dispose() }
$existing = Get-DiskImage -ImagePath $resolved
if ($existing.Attached) {
    throw 'Fixture is already attached; refusing to manage an existing mount.'
}

$attached = $false
try {
    Mount-DiskImage -ImagePath $resolved -Access ReadOnly | Out-Null
    $attached = $true
    $disk = Get-DiskImage -ImagePath $resolved | Get-Disk
    if (-not $disk.IsReadOnly) { throw 'Windows did not mount the fixture read-only.' }
    $partition = $disk | Get-Partition | Where-Object { $_.DriveLetter } | Select-Object -First 1
    if (-not $partition) { throw 'Windows did not assign the NTFS partition a drive letter.' }
    $root = "$($partition.DriveLetter):\"
    & (Join-Path $PSScriptRoot 'capture_chkdsk_reference.ps1') -VolumeRoot $root -CaseId $CaseId -OutputDirectory $OutputDirectory
}
finally {
    if ($attached) { Dismount-DiskImage -ImagePath $resolved | Out-Null }
}
