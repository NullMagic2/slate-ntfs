<!--
Module: documentation.wsl_testing
Purpose: Document Stock WSL module test.
Created: 2026-10-02
Architecture: Explains WSL build and validation procedures; the kernel tests and package helpers
implement those procedures.
-->

# Stock WSL module test

The module was loaded on the **unchanged** Microsoft WSL
`6.18.33.2-microsoft-standard-WSL2` kernel. Its running configuration has
`CONFIG_MODULES=y`, `CONFIG_MODVERSIONS=y`, and no `CONFIG_RUST=y`. Matching
module CRCs came from that kernel's exact source tag and running configuration.
No `.wslconfig` change or custom kernel boot was needed.

The following recipe was verified in Ubuntu 26.04 WSL. It is specific to that
kernel release; use the source tag and compiler capabilities matching a
different running kernel rather than reusing its `Module.symvers`.

```sh
sudo apt-get install build-essential flex bison dwarves libssl-dev \
    libelf-dev cpio rsync gcc-13 gcc-13-plugin-dev

git clone --depth 1 --single-branch -b linux-msft-wsl-6.18.y \
    https://github.com/microsoft/WSL2-Linux-Kernel.git /var/tmp/ntfs-rs-wsl-kernel
cd /var/tmp/ntfs-rs-wsl-kernel
git fetch --depth 1 origin tag linux-msft-wsl-6.18.33.2
git checkout --detach tags/linux-msft-wsl-6.18.33.2
zcat /proc/config.gz > .config
make CC=gcc-13 HOSTCC=gcc-13 RUSTC=/bin/false olddefconfig
make -j8 CC=gcc-13 HOSTCC=gcc-13 RUSTC=/bin/false LOCALVERSION= vmlinux
cp vmlinux.symvers Module.symvers
make -s CC=gcc-13 HOSTCC=gcc-13 RUSTC=/bin/false LOCALVERSION= kernelrelease
```

The final command must print the running `uname -r`. Verify the generated
`module_layout` CRC against one of the WSL supplied modules with
`modprobe --dump-modversions`; a different CRC means the build configuration
or compiler capabilities do not match. Do not override module-version checks.

In this repository, use a current Rust toolchain with `rust-src`, then run:

```sh
KDIR=/var/tmp/ntfs-rs-wsl-kernel \
KBUILD_CC=gcc-13 KBUILD_HOSTCC=gcc-13 KBUILD_RUSTC=/bin/false \
LOCALVERSION= ./build.sh
bash ./kernel/tests/test_wsl_module.sh
```

The test creates a temporary NTFS image, loads the module, mounts it read-only,
checks root and nested directory lookup, resident and nonresident file reads,
and write/remount refusal, then unloads the module. Pass `512` or `8192` to
test other cluster sizes. Use `./kernel/tests/test_image_reads.sh` for image parser and FFI tests.
# NTFS userspace discovery

From PowerShell in this project directory, run
`./ntfs_utils/tests/test_bindings_wsl.ps1`. It builds `ntfs_utils` as your normal WSL user,
then runs the disposable NTFS image test as WSL root. Root can attach the
image to `/dev/loopN` read-only and test Rust/C/Python discovery without
touching a physical disk. The loop device is detached when the test exits.

