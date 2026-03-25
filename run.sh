#!/bin/bash
set -e

# Build the kernel for UEFI target
echo "Building the kernel (UEFI target)..."
# We need to build with -Zbuild-std since we're no_std but need some core/alloc features
cargo build -p kernel --target x86_64-unknown-uefi -Zbuild-std=core,alloc

KERNEL_EFI="target/x86_64-unknown-uefi/debug/kernel.efi"

# Create a temporary directory for the FAT-emulated disk
EFI_ROOT="efi_root"
rm -rf "$EFI_ROOT"
mkdir -p "$EFI_ROOT/EFI/BOOT"

# In UEFI, the default boot file for x64 is /EFI/BOOT/BOOTX64.EFI
cp "$KERNEL_EFI" "$EFI_ROOT/EFI/BOOT/BOOTX64.EFI"

# Run in QEMU using its built-in FAT emulation (VVFAT) pointing to EFI_ROOT
echo "Running in QEMU (using UEFI boot)..."
qemu-system-x86_64 \
    -smp 2 \
    -accel tcg,thread=multi \
    -device virtio-gpu-pci \
    -bios DEBUGX64_OVMF.fd \
    -drive file=fat:rw:"$EFI_ROOT",format=raw \
    -serial stdio \
    -m 256M
