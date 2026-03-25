#!/bin/bash
set -e

# Build the kernel for the freestanding target so Limine can load it directly.
echo "Building the kernel (Limine target)..."
cargo build -p kernel

KERNEL_BIN="target/x86_64-unknown-none/debug/kernel"
LIMINE_BOOT="limine/bin/BOOTX64.EFI"
ROOTFS_IMG="rootfs.img"
STAGE3_TARBALL="${GENTOO_STAGE3_TARBALL:-}"
STAGING_DIR="${GENTOO_STAGE3_STAGING:-stage3-root}"
KERNEL_INIT="${KERNEL_INIT:-}"
KERNEL_ROOT="${KERNEL_ROOT:-/dev/vda}"
KERNEL_ROOTFSTYPE="${KERNEL_ROOTFSTYPE:-crabfs}"
KERNEL_CMDLINE="${KERNEL_CMDLINE:-}"

if [ -n "$STAGE3_TARBALL" ]; then
    echo "Importing Gentoo stage3 into $ROOTFS_IMG..."
    ./tools/import_rootfs.sh "$STAGE3_TARBALL" "$STAGING_DIR" "$ROOTFS_IMG"
elif [ ! -f "$ROOTFS_IMG" ]; then
    echo "Creating placeholder rootfs image at $ROOTFS_IMG (64MiB)..."
    dd if=/dev/zero of="$ROOTFS_IMG" bs=1048576 count=64 status=none
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
