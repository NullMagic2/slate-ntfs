# Module: tests.windows.verify_repair_interop
# Purpose: Check staged repair images with native read-only Windows tools.
# Created: 2026-10-02
# Architecture: Consumes disposable VHDs prepared by the host; attaches each read-only and
# captures chkdsk results.

# Run explicitly as Administrator inside Windows on the staged disposable VHDs.
# chkdsk runs without /f; each VHD is attached read-only and then detached.
param([Parameter(Mandatory=$true)][string]$Stage)
$ErrorActionPreference = 'Stop'
$Stage = (Resolve-Path -LiteralPath $Stage).Path
$vhds = @(Get-ChildItem -LiteralPath $Stage -Filter '*.vhd' -File)
if ($vhds.Count -eq 0) { throw 'No staged VHD images' }
foreach ($vhd in $vhds) {
    $before = (Get-FileHash -LiteralPath $vhd.FullName -Algorithm SHA256).Hash
    $mounted = Mount-DiskImage -ImagePath $vhd.FullName -Access ReadOnly -PassThru
    try {
        $volumes = @(Get-DiskImage -ImagePath $vhd.FullName | Get-Disk | Get-Partition |
            Get-Volume | Where-Object { $_.FileSystem -eq 'NTFS' -and $_.DriveLetter })
        if ($volumes.Count -ne 1) { throw "Expected one lettered NTFS volume in $($vhd.Name)" }
        $drive = [string]$volumes[0].DriveLetter + ':'
        Get-Item -LiteralPath ($drive + '\') | Out-Null
        & chkdsk.exe $drive
        if ($LASTEXITCODE -ne 0) { throw "Windows chkdsk reported exit $LASTEXITCODE on $($vhd.Name)" }
        Write-Host "PASS Windows read-only mount and chkdsk: $($vhd.Name)"
    }
    finally {
        Dismount-DiskImage -ImagePath $vhd.FullName -ErrorAction Stop
    }
    $after = (Get-FileHash -LiteralPath $vhd.FullName -Algorithm SHA256).Hash
    if ($after -ne $before) { throw "Read-only Windows check changed $($vhd.Name)" }
}
