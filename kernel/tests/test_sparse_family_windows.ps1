# Module: kernel.tests.sparse_family_windows
# Purpose: Build a native sparse file whose mappings require many extension records.
# Created: 2026-10-21
# Architecture: Runs only on an explicitly selected disposable Windows data volume.
param([Parameter(Mandatory=$true)][string]$Drive)
$ErrorActionPreference = 'Stop'
if ($Drive -notmatch '^[D-Z]:$') { throw 'A disposable non-system drive is required' }
$File = Join-Path ($Drive + '\') 'sparse-family.bin'
if (Test-Path -LiteralPath $File) { throw 'Fixture already exists' }
$SparseUnitBytes = 64KB
$FileBytes = 512MB
$ChunkBytes = 1MB
$Payload = New-Object byte[] $ChunkBytes
for ($Index = 0; $Index -lt $Payload.Length; $Index++) { $Payload[$Index] = 78 }
$Stream = [IO.File]::Open($File, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
try {
    for ($Offset = 0; $Offset -lt $FileBytes; $Offset += $ChunkBytes) {
        $Stream.Write($Payload, 0, $Payload.Length)
    }
    $Stream.Flush($true)
} finally {
    $Stream.Dispose()
}
$Output = & fsutil.exe sparse setflag $File 2>&1
if ($LASTEXITCODE) { throw ($Output -join ' ') }
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class SparseFamilyFixture {
    private const uint SetZeroData = 0x000980c8;
    [StructLayout(LayoutKind.Sequential)]
    private struct Range {
        public long Start;
        public long End;
    }
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool DeviceIoControl(SafeFileHandle file, uint code,
        ref Range range, uint inputBytes, IntPtr output, uint outputBytes,
        out uint returnedBytes, IntPtr overlapped);
    public static void Punch(SafeFileHandle file, long start, long length) {
        var range = new Range { Start=start, End=start+length };
        uint returned;
        if (!DeviceIoControl(file, SetZeroData, ref range,
            (uint)Marshal.SizeOf<Range>(), IntPtr.Zero, 0, out returned, IntPtr.Zero)) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}
'@
$Stream = [IO.File]::Open($File, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
try {
    for ($Offset = $SparseUnitBytes; $Offset -lt $FileBytes; $Offset += 2 * $SparseUnitBytes) {
        [SparseFamilyFixture]::Punch($Stream.SafeFileHandle, $Offset, $SparseUnitBytes)
    }
    $Stream.Flush($true)
} finally {
    $Stream.Dispose()
}
@{file='sparse-family.bin';length=(Get-Item -LiteralPath $File).Length;sha256=(Get-FileHash -LiteralPath $File).Hash} | ConvertTo-Json -Compress
