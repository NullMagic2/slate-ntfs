#!/usr/bin/env bash
# Module: packaging.debian.build
# Purpose: Build an installable package with userspace tools and DKMS sources.
# Created: 2026-10-01
# Architecture: Stages the shared Rust core, kernel adapters and desktop policy;
# package maintainer scripts build and activate a matching kernel module.

set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
profile=${1:?profile is required}
output=${2:-"$repo/../../outputs"}
mkdir -p "$output"
stage=$(mktemp -d "${TMPDIR:-/tmp}/slate-ntfs-deb.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT

[[ "${3:-amd64}" == amd64 ]] || { echo 'This generator builds amd64 packages only' >&2; exit 1; }
[[ $(uname -m) == x86_64 ]] || { echo 'Build amd64 packages on an x86_64 Linux host' >&2; exit 1; }
arch=amd64
target=${SLATE_PACKAGE_TOOL_TARGET:-x86_64-unknown-linux-musl}
case "$target" in
    x86_64-unknown-linux-musl) ;;
    x86_64-unknown-linux-gnu)
        [[ "$profile" == ubuntu26.04 ]] || {
            echo 'Native tools are supported only for the Ubuntu 26.04 package' >&2
            exit 1
        }
        ;;
    *) echo "Unsupported package tool target: $target" >&2; exit 1 ;;
esac
entry=$(awk -F '|' -v p="$profile" '$2 == p { print; count++ } END { if (count != 1) exit 1 }' "$here/../profiles.tsv") || {
    echo "Unknown package profile: $profile" >&2; exit 1;
}
IFS='|' read -r _ _ label os_id os_version headers min_libc <<< "$entry"
version=${SLATE_PACKAGE_VERSION:-"0.6.7-2~$profile"}
dpkg --validate-version "$version"
prebuilt_library=0
[[ "$profile" != ubuntu26.04 ]] || prebuilt_library=1
case "$profile" in
    ubuntu26.04) rust_dependencies=', cargo (>= 1.93), rustc (>= 1.93), rust-src (>= 1.93)' ;;
    *) rust_dependencies='' ;;
esac

source_tree="$stage/source"
mkdir -p "$source_tree/src" "$source_tree/kernel/rust" "$source_tree/ntfs_utils"
cp "$repo/Cargo.toml" "$repo/Cargo.lock" "$repo/COPYING" "$source_tree/"
cp "$repo/src/format.rs" "$repo/src/lib.rs" "$source_tree/src/"
cp -a "$repo/src/crypto" "$repo/src/engine" "$repo/src/ondisk" \
    "$repo/src/ops" "$source_tree/src/"
mkdir -p "$source_tree/src/tools"
tar -C "$repo/src/tools" --exclude=target --exclude=__pycache__ -cf - . | \
    tar -C "$source_tree/src/tools" -xf -
cp "$repo/kernel/Makefile" "$repo/kernel/vfs_bridge.c" \
    "$repo/kernel/core_fingerprint.sh" \
    "$repo/kernel/freestanding.rs" "$repo/kernel/ntfs_parser.rs" \
    "$repo/kernel/writer.rs" "$source_tree/kernel/"
cp "$repo/kernel/rust/Cargo.toml" "$repo/kernel/rust/Cargo.lock" \
    "$source_tree/kernel/rust/"
cp -a "$repo/ntfs_utils/src" "$source_tree/ntfs_utils/"
cp "$repo/ntfs_utils/README.md" "$source_tree/ntfs_utils/"
cp "$repo/ntfs_utils/Cargo.toml" "$repo/ntfs_utils/Cargo.lock" \
    "$source_tree/ntfs_utils/"
cp "$here/dkms.conf" \
    "$source_tree/dkms.conf"
cp "$here/dkms-build.sh" \
    "$source_tree/dkms-build.sh"
cp "$here/vendor.tar.gz" "$here/vendor.sha256" "$source_tree/"
# Check all shipped application lockfiles against the offline dependency bundle.
# Resolve from the staged source without changing the persistent build cache.
(cd "$source_tree" && sha256sum -c vendor.sha256 && tar -xzf vendor.tar.gz)
for manifest in ntfs_utils/Cargo.toml src/tools/Cargo.toml kernel/rust/Cargo.toml; do
    (cd "$source_tree" && cargo metadata --manifest-path "$manifest" \
        --locked --offline --format-version 1 \
        --config 'source.crates-io.replace-with="vendored-sources"' \
        --config 'source.vendored-sources.directory="vendor"' >/dev/null)
done
rm -rf -- "$stage/vendor-perm"
mv "$source_tree/vendor" "$stage/vendor-perm"
rustup_binary=$(command -v rustup || true)
[[ -n "$rustup_binary" ]] || { echo 'Install rustup to build portable tools and bundle the DKMS fallback' >&2; exit 1; }
cp "$rustup_binary" "$source_tree/rustup"
find "$source_tree" -type f -exec chmod 0644 {} +
chmod 0755 "$source_tree/dkms-build.sh" "$source_tree/rustup"

# Keep compilation independent of the disposable package staging directory.
# Stable source paths and target directories let Cargo reuse unchanged builds.
export CARGO_TARGET_DIR="${SLATE_PACKAGE_BUILD_CACHE:-$repo/target/deb-build/$arch}"
mkdir -p "$CARGO_TARGET_DIR"
if [[ "$target" == x86_64-unknown-linux-musl ]]; then
    export RUSTFLAGS='-C linker=rust-lld -C target-feature=+crt-static'
    rustup target add "$target"
else
    # Ubuntu's compiler already supplies its native target. Keep these tools
    # dynamically linked and constrain the package to that distribution.
    export RUSTFLAGS=''
fi
cargo build --manifest-path "$repo/src/tools/Cargo.toml" \
    --release --locked --target "$target" --bins
cargo build --manifest-path "$repo/ntfs_utils/Cargo.toml" \
    --release --locked --target "$target" --bins
# Native shared library; Ubuntu 26.04 installs it directly.
# Older profiles rebuild it against the target libc during installation.
RUSTFLAGS='-C link-arg=-Wl,-soname,libntfs_utils.so.0' cargo build \
    --manifest-path "$repo/ntfs_utils/Cargo.toml" --release --locked --lib
triplet=$(gcc -dumpmachine)
if (( prebuilt_library )); then
    # Reject a build host whose libc produces an incompatible API library.
    required_libc=$(readelf --version-info "$CARGO_TARGET_DIR/release/libntfs_utils.so" | \
        sed -n 's/.*Name: GLIBC_\([0-9.]*\).*/\1/p' | sort -V | tail -n 1)
    [[ -n "$required_libc" ]] || { echo 'Cannot determine library libc requirement' >&2; exit 1; }
    dpkg --compare-versions "$required_libc" le "$min_libc" || {
        echo "Build library against glibc $min_libc or older (host requires $required_libc)" >&2
        exit 1
    }
fi

package="$stage/package"
module_source="$package/usr/src/slate-ntfs-0.6.7-2"
mkdir -p "$package/DEBIAN" "$(dirname "$module_source")" \
    "$package/usr/bin" "$package/usr/sbin" \
    "$package/usr/lib/slate-ntfs" \
    "$package/usr/share/doc/slate-ntfs" \
    "$package/etc/modprobe.d" "$package/etc/modules-load.d" \
    "$package/sbin" \
    "$package/usr/share/initramfs-tools/hooks" \
    "$package/usr/share/initramfs-tools/scripts/local-top" \
    "$package/usr/lib/systemd/system-shutdown"
cp -a "$source_tree" "$module_source"
for tool in ntfs-inspect ntfs-checkfs ntfs-bitlocker; do
    install -m 0755 "$CARGO_TARGET_DIR/$target/release/$tool" "$package/usr/bin/$tool"
done
for tool in ntfs-chkdsk; do
    install -m 0755 "$CARGO_TARGET_DIR/$target/release/$tool" "$package/usr/sbin/$tool"
done
install -m 0755 "$CARGO_TARGET_DIR/$target/release/fsck_ntfsrs" \
    "$package/usr/sbin/fsck.ntfsrs"
for tool in ntfs-mount ntfs-format ntfs-permissions ntfs-run ntfs-automount; do
    install -m 0755 "$CARGO_TARGET_DIR/$target/release/$tool" "$package/usr/bin/$tool"
done
mkdir -p "$package/usr/lib/$triplet/pkgconfig" "$package/usr/include" \
    "$package/usr/lib/python3/dist-packages/ntfs_utils" \
    "$package/usr/lib/udev/rules.d" "$package/usr/lib/systemd/system" \
    "$package/etc/slate-ntfs"
install -m 0755 "$CARGO_TARGET_DIR/release/libntfs_utils.so" "$package/usr/lib/$triplet/libntfs_utils.so.0"
ln -s libntfs_utils.so.0 "$package/usr/lib/$triplet/libntfs_utils.so"
install -m 0644 "$repo/ntfs_utils/include/ntfs_utils.h" "$package/usr/include/ntfs_utils.h"
install -m 0644 "$repo/ntfs_utils/python/ntfs_utils/__init__.py" "$package/usr/lib/python3/dist-packages/ntfs_utils/__init__.py"
ln -s "/usr/lib/$triplet/libntfs_utils.so.0" "$package/usr/lib/python3/dist-packages/ntfs_utils/libntfs_utils.so"
install -m 0644 "$here/90-slate-ntfs.rules" "$package/usr/lib/udev/rules.d/90-slate-ntfs.rules"
install -m 0644 "$here/slate-ntfs-automount@.service" "$here/slate-ntfs-session.service" "$package/usr/lib/systemd/system/"
install -m 0644 "$here/settings.conf" "$package/etc/slate-ntfs/settings.conf"
case "$profile" in
    ubuntu*|linuxmint*)
        printf '/media\n' > "$package/etc/slate-ntfs/mount-root"
        printf 'SUBSYSTEM=="block", ENV{ID_FS_TYPE}=="ntfs", ENV{UDISKS_AUTO}="0"\n' > "$package/usr/lib/udev/rules.d/95-slate-ntfs-mount-root.rules"
        printf '/etc/slate-ntfs/mount-root\n' >> "$package/DEBIAN/conffiles.extra"
        ;;
esac
cat > "$package/usr/lib/$triplet/pkgconfig/ntfs_utils.pc" <<EOF
prefix=/usr
libdir=/usr/lib/$triplet
includedir=/usr/include
Name: ntfs_utils
Description: Slate NTFS device and administration API
Version: 0.6.7-2
Libs: -L\${libdir} -lntfs_utils
Cflags: -I\${includedir}
EOF
cat > "$package/DEBIAN/conffiles" <<EOF
/etc/slate-ntfs/settings.conf
/etc/modprobe.d/slate-ntfs.conf
/etc/modules-load.d/ntfs_rs.conf
EOF
if [[ -f "$package/DEBIAN/conffiles.extra" ]]; then
    cat "$package/DEBIAN/conffiles.extra" >> "$package/DEBIAN/conffiles"
    rm "$package/DEBIAN/conffiles.extra"
fi
install -m 0755 "$here/mount-ntfs" "$package/sbin/mount.ntfs"
# NTFS Permissions: GTK 3 per-drive access manager and its privileged backend.
perm="$repo/permissions"
# Native Rust + GTK 3 programs (needs libgtk-3-dev on the build host). The
# window links GTK; the root helper is built without it.
(cd "$perm/rust" && cargo build --release --locked --offline \
    --config 'source.crates-io.replace-with="vendored-sources"' \
    --config "source.vendored-sources.directory=\"$stage/vendor-perm\"" \
    --target-dir "$CARGO_TARGET_DIR/permissions")
install -D -m 0755 "$CARGO_TARGET_DIR/permissions/release/slate-ntfs-permissions" "$package/usr/bin/slate-ntfs-permissions"
install -D -m 0755 "$CARGO_TARGET_DIR/permissions/release/slate-ntfs-policy" "$package/usr/lib/slate-ntfs/slate-ntfs-policy"
# One shortcut per person at login: desktop icon, or the Dash on icon-less GNOME.
install -D -m 0755 "$perm/desktop-shortcut" "$package/usr/lib/slate-ntfs/desktop-shortcut"
install -D -m 0644 "$perm/slate-ntfs-desktop-shortcut.desktop" "$package/etc/xdg/autostart/slate-ntfs-desktop-shortcut.desktop"
install -D -m 0644 "$perm/slate-ntfs-permissions.desktop" "$package/usr/share/applications/slate-ntfs-permissions.desktop"
install -D -m 0644 "$perm/org.slate-ntfs.permissions.policy" "$package/usr/share/polkit-1/actions/org.slate-ntfs.permissions.policy"
install -D -m 0644 "$perm/app-icon/256.png" "$package/usr/share/pixmaps/slate-ntfs-permissions.png"
for size in 16 24 32 48 64 128 256 512; do
    install -D -m 0644 "$perm/app-icon/$size.png" "$package/usr/share/icons/hicolor/${size}x${size}/apps/slate-ntfs-permissions.png"
done
(cd "$perm/icons" && find . -type f) | while read -r icon; do
    install -D -m 0644 "$perm/icons/$icon" "$package/usr/share/slate-ntfs/icons/$icon"
done
ln -s mount.ntfs "$package/sbin/mount.ntfs3"
ln -s mount.ntfs "$package/sbin/mount.ntfs-3g"
ln -s mount.ntfs "$package/sbin/mount.ntfsrs"
install -m 0644 "$here/ntfs-modules.conf" \
    "$package/etc/modprobe.d/slate-ntfs.conf"
install -m 0644 "$here/ntfs_rs.modules-load" \
    "$package/etc/modules-load.d/ntfs_rs.conf"
install -m 0755 "$repo/boot/initramfs-tools/hooks/ntfsrs" \
    "$package/usr/share/initramfs-tools/hooks/ntfsrs"
install -m 0755 "$repo/boot/initramfs-tools/scripts/local-top/ntfsrs" \
    "$package/usr/share/initramfs-tools/scripts/local-top/ntfsrs"
install -m 0755 "$repo/boot/systemd/system-shutdown/ntfsrs" \
    "$package/usr/lib/systemd/system-shutdown/ntfsrs"
install -m 0644 "$here/README.md" \
    "$package/usr/share/doc/slate-ntfs/README.md"
install -m 0644 "$repo/COPYING" "$package/usr/share/doc/slate-ntfs/copyright"
install -m 0644 "$repo/ntfs_utils/README.md" "$package/usr/share/doc/slate-ntfs/API.md"
for script in postinst prerm postrm; do
    install -m 0755 "$here/$script" "$package/DEBIAN/$script"
done
cat > "$package/usr/lib/slate-ntfs/package-profile" <<EOF
SLATE_TARGET_ID=$os_id
SLATE_TARGET_VERSION_ID=$os_version
SLATE_PREBUILT_LIBRARY=$prebuilt_library
EOF
cat > "$package/DEBIAN/control" <<EOF
Package: slate-ntfs
Version: $version
Section: kernel
Priority: optional
Architecture: $arch
Maintainer: Slate NTFS contributors <slate-ntfs@example.invalid>
Depends: python3, libgtk-3-0t64 | libgtk-3-0, pkexec | policykit-1, acl, udisks2, udev, util-linux, dkms, initramfs-tools, kmod, build-essential, binutils, dwarves, ca-certificates, $headers, libc6 (>= $min_libc), libgcc-s1$rust_dependencies
Conflicts: ntfs-3g
Description: Slate NTFS driver and tools for $label
 DKMS builds ntfs_rs for the running kernel and future kernel updates.
 Includes NTFS tools, hotplug integration, C library and Python bindings.
EOF
installed_size=$(du -sk --exclude=DEBIAN "$package" | cut -f1)
printf 'Installed-Size: %s\n' "$installed_size" >> "$package/DEBIAN/control"
(cd "$package" && find . -type f ! -path './DEBIAN/*' -print0 | \
    LC_ALL=C sort -z | xargs -0 md5sum | sed 's#  \./#  #' > DEBIAN/md5sums)
package_path="$output/slate-ntfs_${version}_${arch}.deb"
dpkg-deb --build --root-owner-group "$package" "$package_path"
dpkg-deb --info "$package_path"
