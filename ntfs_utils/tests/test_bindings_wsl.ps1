# Module: ntfs_utils.tests.bindings_wsl
# Purpose: Run the userspace binding checks through WSL.
# Created: 2026-10-02
# Architecture: Builds the utility library as the normal user; the shell binding suite manages
# disposable loop devices.

$ErrorActionPreference = 'Stop'
$project = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path

# Build as the normal WSL user so the checkout's Cargo outputs stay usable.
& wsl.exe --cd $project bash -lc 'cargo build --manifest-path ntfs_utils/Cargo.toml --release --locked'
if ($LASTEXITCODE -ne 0) { throw "WSL userspace library build failed ($LASTEXITCODE)" }

# Loop-device attachment needs root in the WSL distro. The test uses only a
# disposable image and detaches its loop device on exit.
& wsl.exe --cd $project -u root bash -lc 'SKIP_CARGO_BUILD=1 bash ./ntfs_utils/tests/test_bindings.sh'
if ($LASTEXITCODE -ne 0) { throw "WSL NTFS image/loop-device test failed ($LASTEXITCODE)" }
