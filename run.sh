#!/bin/bash
set -e

# Build the kernel for the freestanding target so Limine can load it directly.
echo "Building the kernel (Limine target)..."
cargo build -p kernel

KERNEL_BIN="target/x86_64-unknown-none/debug/kernel"
LIMINE_BOOT="limine/bin/BOOTX64.EFI"

# Create a temporary directory for the FAT-emulated Limine disk.
EFI_ROOT="efi_root"
rm -rf "$EFI_ROOT"
mkdir -p "$EFI_ROOT/EFI/BOOT"
mkdir -p "$EFI_ROOT/boot/limine"

cp "$LIMINE_BOOT" "$EFI_ROOT/EFI/BOOT/BOOTX64.EFI"
cp "$KERNEL_BIN" "$EFI_ROOT/kernel"
cat > "$EFI_ROOT/limine.conf" <<'EOF'
timeout: 0
verbose: yes

/Linux-Like Kernel
    protocol: limine
    path: boot():/kernel
EOF
cp "$EFI_ROOT/limine.conf" "$EFI_ROOT/boot/limine/limine.conf"
cp "$EFI_ROOT/limine.conf" "$EFI_ROOT/EFI/BOOT/limine.conf"

# Run in QEMU using Limine's UEFI binary as the default boot application.
echo "Running in QEMU (using Limine UEFI boot)..."
qemu-system-x86_64 \
    -smp 2 \
    -accel tcg,thread=multi \
    -bios DEBUGX64_OVMF.fd \
    -drive file=fat:rw:"$EFI_ROOT",format=raw \
    -serial stdio \
    -display none \
    -m 256M
