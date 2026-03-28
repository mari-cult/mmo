#!/usr/bin/env brush
set -e

# Build the kernel for the freestanding target so Limine can load it directly.
echo "Building the kernel (Limine target)..."
KERNEL_RUSTFLAGS="${KERNEL_RUSTFLAGS:-}"
if [ -n "$KERNEL_RUSTFLAGS" ]; then
    RUSTFLAGS="$KERNEL_RUSTFLAGS" cargo build -p kernel
else
    cargo build -p kernel
fi

KERNEL_BIN="target/x86_64-unknown-none/debug/kernel"
LIMINE_BOOT="limine/bin/BOOTX64.EFI"
ROOTFS_IMG="rootfs.img"
STAGE3_TARBALL="${GENTOO_STAGE3_TARBALL:-}"
STAGING_DIR="${GENTOO_STAGE3_STAGING:-stage3-root}"
KERNEL_INIT="${KERNEL_INIT:-}"
KERNEL_ROOT="${KERNEL_ROOT:-/dev/vda}"
KERNEL_ROOTFSTYPE="${KERNEL_ROOTFSTYPE:-crabfs}"
KERNEL_CMDLINE="${KERNEL_CMDLINE:-}"
ROOTFS_SIZE_MIB="${ROOTFS_SIZE_MIB:-}"
EMPTY_ROOTFS_DIR=".empty-rootfs"

resolve_rootfs_size_mib() {
    local source_dir="$1"
    if [ -n "$ROOTFS_SIZE_MIB" ]; then
        printf '%s\n' "$ROOTFS_SIZE_MIB"
        return
    fi

    local used_mib size_mib
    used_mib="$(du -sm "$source_dir" | awk '{print $1}')"
    size_mib=$((used_mib + used_mib / 4 + 256))
    if [ "$size_mib" -lt 64 ]; then
        size_mib=64
    fi
    printf '%s\n' "$size_mib"
}

build_rootfs_from_dir() {
    local source_dir="$1"
    local output_img="$2"
    local host_target
    local size_mib
    host_target="$(rustc -vV | awk '/host:/ {print $2}')"
    size_mib="$(resolve_rootfs_size_mib "$source_dir")"
    cargo run --offline --manifest-path tools/mkrootfs/Cargo.toml --target "$host_target" \
        --config 'unstable.build-std=["std","panic_abort"]' -- \
        --source "$source_dir" \
        --output "$output_img" \
        --size-mib "$size_mib"
}

rootfs_has_crabfs_superblock() {
    [ -f "$1" ] || return 1
    [ "$(head -c 4 "$1" | xxd -p -c 4 2>/dev/null)" = "58465342" ]
}

if [ -n "$STAGE3_TARBALL" ]; then
    echo "Importing Gentoo stage3 into $ROOTFS_IMG..."
    ./tools/import_rootfs.sh "$STAGE3_TARBALL" "$STAGING_DIR" "$ROOTFS_IMG"
elif [ -d "$STAGING_DIR" ]; then
    echo "Packing existing rootfs tree from $STAGING_DIR into $ROOTFS_IMG..."
    build_rootfs_from_dir "$STAGING_DIR" "$ROOTFS_IMG"
elif ! rootfs_has_crabfs_superblock "$ROOTFS_IMG"; then
    echo "Creating minimal crabfs rootfs image at $ROOTFS_IMG..."
    rm -rf "$EMPTY_ROOTFS_DIR"
    mkdir -p "$EMPTY_ROOTFS_DIR"
    build_rootfs_from_dir "$EMPTY_ROOTFS_DIR" "$ROOTFS_IMG"
fi

# Create a temporary directory for the FAT-emulated Limine disk.
EFI_ROOT="efi_root"
rm -rf "$EFI_ROOT"
mkdir -p "$EFI_ROOT/EFI/BOOT"
mkdir -p "$EFI_ROOT/boot/limine"

cp "$LIMINE_BOOT" "$EFI_ROOT/EFI/BOOT/BOOTX64.EFI"
cp "$KERNEL_BIN" "$EFI_ROOT/kernel"
if [ -z "$KERNEL_CMDLINE" ]; then
    KERNEL_CMDLINE="root=${KERNEL_ROOT} rootfstype=${KERNEL_ROOTFSTYPE}"
    if [ -n "$KERNEL_INIT" ]; then
        KERNEL_CMDLINE="${KERNEL_CMDLINE} init=${KERNEL_INIT}"
    fi
fi
cat > "$EFI_ROOT/limine.conf" <<'EOF'
timeout: 0
verbose: yes

/Linux-Like Kernel
    protocol: limine
    path: boot():/kernel
    cmdline: __KERNEL_CMDLINE__
EOF
python3 - <<'PY' "$EFI_ROOT/limine.conf" "$KERNEL_CMDLINE"
from pathlib import Path
import sys
conf = Path(sys.argv[1])
cmdline = sys.argv[2]
conf.write_text(conf.read_text().replace("__KERNEL_CMDLINE__", cmdline))
PY
cp "$EFI_ROOT/limine.conf" "$EFI_ROOT/boot/limine/limine.conf"
cp "$EFI_ROOT/limine.conf" "$EFI_ROOT/EFI/BOOT/limine.conf"

# Run in QEMU using Limine's UEFI binary as the default boot application.
echo "Running in QEMU (using Limine UEFI boot)..."
qemu-system-x86_64 \
    -smp 2 \
    -accel tcg,thread=multi \
    -bios DEBUGX64_OVMF.fd \
    -drive file=fat:rw:"$EFI_ROOT",format=raw \
    -drive if=none,id=drv0,file="$ROOTFS_IMG",format=raw \
    -device virtio-blk-pci,drive=drv0 \
    -serial stdio \
    -display none \
    -m 256M
