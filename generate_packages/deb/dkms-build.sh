#!/usr/bin/env bash
# Module: packaging.debian.dkms_build
# Purpose: Build the freestanding Rust core and matching kernel module.
# Created: 2026-10-01
# Architecture: DKMS invokes this adapter for installed kernel headers and packaged source.

set -euo pipefail

library_only=0
if [[ "${1:-}" == --library-only ]]; then
    library_only=1
else
    kernel_version=${1:?kernel version is required}
    kernel_dir="/lib/modules/$kernel_version/build"
    [[ -f "$kernel_dir/Makefile" && -f "$kernel_dir/.config" ]] || {
        echo "Slate NTFS: matching configured headers are required for $kernel_version" >&2
        exit 1
    }
fi

case "$(uname -m)" in
    x86_64) kernel_arch=x86; rust_target=x86_64-unknown-none; config=CONFIG_X86_64 ;;
    aarch64) kernel_arch=arm64; rust_target=aarch64-unknown-none-softfloat; config=CONFIG_ARM64 ;;
    *) echo 'Slate NTFS supports only amd64 and arm64' >&2; exit 1 ;;
esac
if (( ! library_only )); then
grep -qx "$config=y" "$kernel_dir/.config" || {
    echo "Slate NTFS: $kernel_version headers have the wrong architecture" >&2
    exit 1
}
fi

cd "$(dirname "$0")"
rustc_bin=$(command -v rustc || true)
cargo_bin=$(command -v cargo || true)
rust_source=''
usable_system_rust=0
if [[ -n "$rustc_bin" && -n "$cargo_bin" ]]; then
    rust_source="$("$rustc_bin" --print sysroot)/lib/rustlib/src/rust"
    rust_version=$("$rustc_bin" --version | awk '{print $2}')
    if { [[ -f "$rust_source/Cargo.lock" ]] ||
         [[ -f "$rust_source/library/Cargo.lock" ]]; } &&
       dpkg --compare-versions "$rust_version" ge 1.93; then
        usable_system_rust=1
    fi
fi
if (( ! usable_system_rust )); then
    export RUSTUP_HOME=/var/lib/slate-ntfs/rustup
    export CARGO_HOME=/var/cache/slate-ntfs/cargo
    mkdir -p "$RUSTUP_HOME" "$CARGO_HOME"
    ./rustup toolchain install 1.97.1 --profile minimal --component rust-src
    rustc_bin=$(./rustup which rustc --toolchain 1.97.1)
    cargo_bin=$(./rustup which cargo --toolchain 1.97.1)
    rust_source="$("$rustc_bin" --print sysroot)/lib/rustlib/src/rust"
fi
[[ -f "$rust_source/Cargo.lock" || -f "$rust_source/library/Cargo.lock" ]] || {
    echo 'Slate NTFS needs matching Rust source with Cargo.lock' >&2; exit 1;
}
export RUSTC="$rustc_bin"
if [[ $("$rustc_bin" --version) == 'rustc 1.93.'* ]]; then
    sha256sum -c vendor.sha256
    # Refresh generated sources so upgrades also fix incomplete vendor trees.
    tar -xzf vendor.tar.gz
    mkdir -p .cargo
    cat > .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF
    cargo_options=(--offline)
else
    echo 'Slate NTFS: using the installed Rust source and online Cargo registry' >&2
    cargo_options=()
fi
if (( library_only )); then
    RUSTFLAGS='-C link-arg=-Wl,-soname,libntfs_utils.so.0' CARGO_TARGET_DIR="$PWD/ntfs_utils/target" \
        "$cargo_bin" build --manifest-path ntfs_utils/Cargo.toml --release --locked --lib "${cargo_options[@]}"
    exit 0
fi
rust_flags='-C panic=abort -C relocation-model=static -C force-frame-pointers=yes'
if [[ "$kernel_arch" == x86 ]]; then
    rust_flags+=' -C no-redzone=yes -C code-model=kernel'
    grep -qx 'CONFIG_MITIGATION_RETHUNK=y' "$kernel_dir/.config" && rust_flags+=' -Zfunction-return=thunk-extern'
    if grep -qx 'CONFIG_MITIGATION_RETPOLINE=y' "$kernel_dir/.config"; then
        rust_flags+=' -Zretpoline-external-thunk=yes -Zplt=yes'
    fi
    grep -qx 'CONFIG_X86_KERNEL_IBT=y' "$kernel_dir/.config" && rust_flags+=' -Zcf-protection=branch -Cjump-tables=n'
else
    rust_flags+=' -C code-model=large'
fi

export CARGO_TARGET_DIR="$PWD/kernel/rust/target"
RUSTC_BOOTSTRAP=1 RUSTFLAGS="$rust_flags" \
    "$cargo_bin" -Z build-std=core,compiler_builtins build \
    --manifest-path kernel/rust/Cargo.toml --release --locked \
    "${cargo_options[@]}" \
    --target "$rust_target"
make -C "$kernel_dir" M="$PWD/kernel" ARCH="$kernel_arch" \
    NTFS_RS_RUST_TARGET="$rust_target" \
    NTFS_RS_RUST_TARGET_DIR="$CARGO_TARGET_DIR" modules
test -s kernel/slate-ntfs.ko
test "$(modinfo -F vermagic kernel/slate-ntfs.ko | cut -d' ' -f1)" = "$kernel_version"
