# Module: kernel.tests.hard_link_deletion_windows
# Purpose: Independently check the mounted D04 witness left by the Linux test.
# Created: 2026-10-21
# Architecture: Reads a disposable returned NTFS image through Windows and runs
# CHKDSK without repair; the host owns attachment, image identity and result capture.

param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Z]$')]
    [string]$Drive
)

$ErrorActionPreference = 'Stop'
$PayloadBytes = 8192
$WitnessNames = @('keep-a.bin', 'keep-b.bin', 'keep-c.bin')
$Root = "${Drive}:\d04-links"
$Entries = @(Get-ChildItem -LiteralPath $Root -Force | Select-Object -ExpandProperty Name | Sort-Object)
if (($Entries -join '|') -ne (($WitnessNames | Sort-Object) -join '|')) {
    throw 'Deleted test directories remain or a witness link is missing.'
}

$Payload = [Text.Encoding]::ASCII.GetBytes(('H' * $PayloadBytes))
$Hasher = [Security.Cryptography.SHA256]::Create()
try {
    $ExpectedHash = ([BitConverter]::ToString($Hasher.ComputeHash($Payload))).Replace('-', '')
} finally {
    $Hasher.Dispose()
}

$Results = @()
foreach ($Name in $WitnessNames) {
    $Path = Join-Path $Root $Name
    $Item = Get-Item -LiteralPath $Path
    $Hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($Item.Length -ne $PayloadBytes -or $Hash -ne $ExpectedHash) {
        throw "Surviving link contents differ: $Name"
    }
    $IdentityOutput = & fsutil.exe file queryfileid $Path 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "File identity query failed: $IdentityOutput"
    }
    $Identity = [regex]::Match(($IdentityOutput -join ' '), '0x[0-9a-fA-F]+').Value
    if (!$Identity) {
        throw "File identity not found: $IdentityOutput"
    }
    $LinkOutput = & fsutil.exe hardlink list $Path 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Hard-link enumeration failed: $LinkOutput"
    }
    $Links = @($LinkOutput | ForEach-Object { "$_".Trim() } | Where-Object { $_.StartsWith('\') })
    $ExpectedLinks = @($WitnessNames | ForEach-Object { "\d04-links\$_" } | Sort-Object)
    if ((($Links | Sort-Object) -join '|') -ne ($ExpectedLinks -join '|')) {
        throw "Windows hard-link names differ: $LinkOutput"
    }
    $Results += @{ name = $Name; identity = $Identity; links = $Links.Count; sha256 = $Hash }
}
if (@($Results.identity | Select-Object -Unique).Count -ne 1) {
    throw 'Witness paths no longer reference one file.'
}

$CheckOutput = @(& chkdsk.exe "${Drive}:" 2>&1 | ForEach-Object { "$_" })
$CheckExit = $LASTEXITCODE
if ($CheckExit -ne 0) {
    throw "CHKDSK failed with exit ${CheckExit}: $($CheckOutput -join [Environment]::NewLine)"
}
@{
    result = 'D04_WINDOWS_PASS'
    chkdsk_exit = $CheckExit
    chkdsk_output = $CheckOutput
    witnesses = $Results
} | ConvertTo-Json -Depth 5 -Compress
