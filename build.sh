#!/usr/bin/env bash
# Module: build
# Purpose: Compile and validate the project artifacts.
# Created: 2026-10-02
# Architecture: Builds the core, utilities and kernel adapter; test.sh owns test selection.

set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if ! command -v cargo >/dev/null 2>&1; then
    echo 'error: cargo is required' >&2
    exit 1
fi

# Compilation and artifact validation only. Select tests with ./test.sh.
# CARGO_BUILD_TARGET (and Cargo's linker configuration) may select cross builds.
cargo_options=(--release --locked)
artifact_suffix=release
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    cargo_options+=(--target "$CARGO_BUILD_TARGET")
    artifact_suffix="$CARGO_BUILD_TARGET/release"
fi
host_target_dir="${CARGO_TARGET_DIR:-$PWD/target}"
kernel_target_dir="${NTFS_RS_KERNEL_TARGET_DIR:-$PWD/kernel/rust/target}"
CARGO_TARGET_DIR="$host_target_dir" cargo build "${cargo_options[@]}"
CARGO_TARGET_DIR="$host_target_dir" cargo build --manifest-path src/tools/Cargo.toml "${cargo_options[@]}"
utils_target_dir="${CARGO_TARGET_DIR:-$PWD/ntfs_utils/target}"
CARGO_TARGET_DIR="$utils_target_dir" cargo build --manifest-path ntfs_utils/Cargo.toml "${cargo_options[@]}"
cp -- "$utils_target_dir/$artifact_suffix/libntfs_utils.so" \
    ntfs_utils/python/ntfs_utils/libntfs_utils.so

echo 'Built NTFS tools, copy-only write lab, and libntfs_utils.so (Rust, C, Python).'
if [[ -n "${KDIR:-}" ]]; then
    if [[ ! -f "$KDIR/Makefile" ]]; then
        echo "error: KDIR is not a kernel build tree: $KDIR" >&2
        exit 1
    fi
    if [[ ! -f "$KDIR/.config" ]]; then
        echo "error: KDIR has no kernel configuration" >&2
        exit 1
    fi
    kernel_arch="${ARCH:-$(uname -m)}"
    case "$kernel_arch" in
        x86_64|x86) kernel_arch=x86; rust_target=x86_64-unknown-none; kernel_config=CONFIG_X86_64 ;;
        aarch64|arm64) kernel_arch=arm64; rust_target=aarch64-unknown-none-softfloat; kernel_config=CONFIG_ARM64 ;;
        *) echo "error: unsupported kernel architecture: $kernel_arch" >&2; exit 1 ;;
    esac
    if ! grep -q "^${kernel_config}=y$" "$KDIR/.config"; then
        echo "error: selected architecture does not match KDIR configuration ($kernel_config)" >&2
        exit 1
    fi
    for tool in rustc "${CROSS_COMPILE:-}nm" "${CROSS_COMPILE:-}readelf"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "error: $tool is required for the freestanding kernel build" >&2
            exit 1
        fi
    done
    rust_source=$(rustc --print sysroot)/lib/rustlib/src/rust
    if [[ ! -f "$rust_source/Cargo.lock" && ! -f "$rust_source/library/Cargo.lock" ]]; then
        echo 'error: Rust source with Cargo.lock is required; install a rustup toolchain with rust-src' >&2
        exit 1
    fi
    rust_flags='-C panic=abort -C relocation-model=static -C force-frame-pointers=yes'
    if [[ "$kernel_arch" == x86 ]]; then
        rust_flags+=' -C no-redzone=yes -C code-model=kernel'
    else
        # Soft-float forbids FP/NEON register use; large model handles kernel VAs.
        rust_flags+=' -C code-model=large'
    fi
    if [[ "$kernel_arch" == x86 ]] && grep -q '^CONFIG_MITIGATION_RETHUNK=y$' "$KDIR/.config"; then
        rust_flags+=' -Zfunction-return=thunk-extern'
    fi
    if [[ "$kernel_arch" == x86 ]] && grep -q '^CONFIG_MITIGATION_RETPOLINE=y$' "$KDIR/.config"; then
        rust_flags+=' -Zretpoline-external-thunk=yes -Zplt=yes'
    fi
    if [[ "$kernel_arch" == x86 ]] && grep -q '^CONFIG_X86_KERNEL_IBT=y$' "$KDIR/.config"; then
        rust_flags+=' -Zcf-protection=branch -Cjump-tables=n'
    fi
    RUSTC_BOOTSTRAP=1 RUSTFLAGS="$rust_flags" \
        CARGO_TARGET_DIR="$kernel_target_dir" cargo -Z build-std=core,compiler_builtins build \
        --manifest-path kernel/rust/Cargo.toml \
        --release --locked --target "$rust_target"
    make_options=("ARCH=$kernel_arch" "NTFS_RS_RUST_TARGET=$rust_target" "NTFS_RS_RUST_TARGET_DIR=$kernel_target_dir")
    [[ -z "${CROSS_COMPILE:-}" ]] || make_options+=("CROSS_COMPILE=$CROSS_COMPILE")
    [[ -z "${KBUILD_CC:-}" ]] || make_options+=("CC=$KBUILD_CC")
    [[ -z "${KBUILD_HOSTCC:-}" ]] || make_options+=("HOSTCC=$KBUILD_HOSTCC")
    [[ -z "${KBUILD_RUSTC:-}" ]] || make_options+=("RUSTC=$KBUILD_RUSTC")
    make -C "$KDIR" M="$PWD/kernel" "${make_options[@]}" modules
    symbol_tool="${CROSS_COMPILE:-}nm"
    relocation_tool="${CROSS_COMPILE:-}readelf"
    # These callbacks are defined by the C bridge in the completed module.
    bridge_symbols='ntfs_rs_(panic|hold_at|release_at|write_data_at|mount_refusal|table_copy|table_epoch|table_store|table_drop)'
    allowed_symbols="^($bridge_symbols)$"
    if [[ "$kernel_arch" == x86 ]]; then
        allowed_symbols="^($bridge_symbols|__x86_return_thunk|__x86_indirect_thunk_[[:alnum:]_]+)$"
    fi
    unexpected=$("$symbol_tool" -u kernel/rust_core.o | awk '{print $NF}' | grep -Ev "$allowed_symbols" || true)
    if [[ -n "$unexpected" ]]; then
        echo "error: freestanding Rust object has unresolved symbols: $unexpected" >&2
        exit 1
    fi
    if [[ "$kernel_arch" == x86 ]] && "$relocation_tool" -rW kernel/slate-ntfs.ko | grep -Eq 'R_X86_64_(GOTPCREL|GOTPCRELX|REX_GOTPCRELX)'; then
        echo 'error: kernel module contains GOT relocations unsupported by the x86_64 module loader' >&2
        exit 1
    fi
    echo 'Built kernel/slate-ntfs.ko without CONFIG_RUST (experimental rw mounts require supported clean volumes and an explicit sidmap).'
else
    echo 'Set KDIR to matching kernel headers to build the kernel module.'
fi
