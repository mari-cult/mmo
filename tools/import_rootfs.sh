#!/bin/bash
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 <rootfs.tar[.gz|.xz|.zst]> <staging_dir> [rootfs.img]"
    exit 1
fi

TARBALL="$1"
STAGING="$2"
ROOTFS_IMG="${3:-}"
SIZE_MIB="${ROOTFS_SIZE_MIB:-4096}"

rm -rf "$STAGING"
mkdir -p "$STAGING"

case "$TARBALL" in
    *.tar.gz|*.tgz) tar --exclude='./dev/*' -xzf "$TARBALL" -C "$STAGING" ;;
    *.tar.xz) tar --exclude='./dev/*' -xJf "$TARBALL" -C "$STAGING" ;;
    *.tar.zst) tar --exclude='./dev/*' --zstd -xf "$TARBALL" -C "$STAGING" ;;
    *.tar) tar --exclude='./dev/*' -xf "$TARBALL" -C "$STAGING" ;;
    *)
        echo "unsupported tarball extension: $TARBALL"
        exit 2
        ;;
esac

find "$STAGING" -mindepth 1 ! -name ".import_manifest" | sed "s#^$STAGING##" | sort > "$STAGING/.import_manifest"
echo "imported rootfs into $STAGING (manifest: $STAGING/.import_manifest)"

if [ -n "$ROOTFS_IMG" ]; then
    HOST_TARGET="$(rustc -vV | awk '/host:/ {print $2}')"
    cargo run --offline --manifest-path tools/mkrootfs/Cargo.toml --target "$HOST_TARGET" \
        --config 'unstable.build-std=["std","panic_abort"]' -- \
        --source "$STAGING" \
        --output "$ROOTFS_IMG" \
        --size-mib "$SIZE_MIB"
fi
