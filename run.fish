#!/usr/bin/env fish

set -q ARCH; or set -g ARCH x86_64
echo "Building for architecture: $ARCH"

set -g TARGET ""
set -g QEMU_BIN ""
set -g QEMU_OPTS ""
set -g LIMINE_BOOT ""
set -g EFI_BOOT_FILE ""

function fetch_ovmf
    set -l file $argv[1]
    set -l url $argv[2]
    if not test -f "$file"
        echo "Fetching $file from $url..."
        curl -L -o "$file" "$url"
    end
end

if test "$ARCH" = "x86_64"
    set TARGET x86_64-unknown-none
    set QEMU_BIN qemu-system-x86_64
    fetch_ovmf DEBUGX64_OVMF.fd https://retrage.github.io/edk2-nightly/bin/DEBUGX64_OVMF.fd
    set QEMU_OPTS -bios DEBUGX64_OVMF.fd
    set LIMINE_BOOT limine/bin/BOOTX64.EFI
    set EFI_BOOT_FILE BOOTX64.EFI
else if test "$ARCH" = "aarch64"
    set TARGET aarch64-unknown-none
    set QEMU_BIN qemu-system-aarch64
    fetch_ovmf DEBUGAARCH64_QEMU_EFI.fd https://retrage.github.io/edk2-nightly/bin/DEBUGAARCH64_QEMU_EFI.fd
    set QEMU_OPTS -machine virt -cpu cortex-a72 -bios DEBUGAARCH64_QEMU_EFI.fd
    set LIMINE_BOOT limine/bin/BOOTAA64.EFI
    set EFI_BOOT_FILE BOOTAA64.EFI
else
    echo "Unsupported architecture: $ARCH"
    exit 1
end

# Build the kernel
echo "Building the kernel (Limine target)..."
set -q KERNEL_RUSTFLAGS; or set KERNEL_RUSTFLAGS ""
if test -n "$KERNEL_RUSTFLAGS"
    env RUSTFLAGS="$KERNEL_RUSTFLAGS" cargo build -p kernel --target "$TARGET"
else
    cargo build -p kernel --target "$TARGET"
end

set -g KERNEL_BIN "target/$TARGET/debug/kernel"
set -g ROOTFS_IMG "rootfs.img"
set -g NATIVE_INIT_DIR "userspace/native_init"
set -g NATIVE_INIT_OBJ "native_init.obj"
set -g NATIVE_INIT_STUBS "native_init_stubs.obj"
set -g NATIVE_INIT_EXE "init.exe"
set -q GENTOO_STAGE3_TARBALL; or set GENTOO_STAGE3_TARBALL ""
set -q GENTOO_STAGE3_STAGING; or set GENTOO_STAGE3_STAGING "stage3-root"
set -q KERNEL_INIT; or set KERNEL_INIT ""
set -q KERNEL_ROOT; or set KERNEL_ROOT "/dev/vda"
set -q KERNEL_ROOTFSTYPE; or set KERNEL_ROOTFSTYPE "crabfs"
set -q KERNEL_CMDLINE; or set KERNEL_CMDLINE ""
set -q ROOTFS_SIZE_MIB; or set ROOTFS_SIZE_MIB ""
set -g EMPTY_ROOTFS_DIR ".empty-rootfs"

function resolve_rootfs_size_mib
    set -l source_dir $argv[1]
    if test -n "$ROOTFS_SIZE_MIB"
        echo "$ROOTFS_SIZE_MIB"
        return
    end

    set -l used_mib (du -sm "$source_dir" | awk '{print $1}')
    set -l size_mib (math -s0 "$used_mib + $used_mib / 4 + 256")
    if test "$size_mib" -lt 64
        set size_mib 64
    end
    echo "$size_mib"
end

function build_rootfs_from_dir
    set -l source_dir $argv[1]
    set -l output_img $argv[2]
    set -l host_target (rustc -vV | awk '/host:/ {print $2}')
    set -l size_mib (resolve_rootfs_size_mib "$source_dir")
    
    cargo run --offline --manifest-path tools/mkrootfs/Cargo.toml --target "$host_target" \
        --config 'unstable.build-std=["std","panic_abort"]' -- \
        --source "$source_dir" \
        --output "$output_img" \
        --size-mib "$size_mib"
end

function build_native_init
    echo "Building native PE32+ init.exe..."
    clang --target=x86_64-pc-windows-msvc -ffreestanding -fno-stack-protector -fno-builtin \
        -c "$NATIVE_INIT_DIR/init.c" -o "$NATIVE_INIT_OBJ"
    clang --target=x86_64-pc-windows-msvc -c "$NATIVE_INIT_DIR/syscall_stubs.S" -o "$NATIVE_INIT_STUBS"
    lld-link /entry:start /subsystem:native /nodefaultlib /machine:x64 \
        /out:"$NATIVE_INIT_EXE" "$NATIVE_INIT_OBJ" "$NATIVE_INIT_STUBS"
end

function install_native_init_to_dir
    set -l target_dir $argv[1]
    mkdir -p "$target_dir/Windows/System32"
    cp "$NATIVE_INIT_EXE" "$target_dir/Windows/System32/init.exe"
end

function rootfs_has_crabfs_superblock
    set -l img $argv[1]
    if not test -f "$img"
        return 1
    end
    set -l magic (head -c 4 "$img" | xxd -p -c 4 2>/dev/null)
    if test "$magic" = "58465342"
        return 0
    else
        return 1
    end
end

build_native_init

if test -n "$GENTOO_STAGE3_TARBALL"
    echo "Importing Gentoo stage3 into $ROOTFS_IMG..."
    ./tools/import_rootfs.sh "$GENTOO_STAGE3_TARBALL" "$GENTOO_STAGE3_STAGING" "$ROOTFS_IMG"
    install_native_init_to_dir "$GENTOO_STAGE3_STAGING"
    build_rootfs_from_dir "$GENTOO_STAGE3_STAGING" "$ROOTFS_IMG"
else if test -d "$GENTOO_STAGE3_STAGING"
    echo "Packing existing rootfs tree from $GENTOO_STAGE3_STAGING into $ROOTFS_IMG..."
    install_native_init_to_dir "$GENTOO_STAGE3_STAGING"
    build_rootfs_from_dir "$GENTOO_STAGE3_STAGING" "$ROOTFS_IMG"
else
    echo "Creating NT rootfs image at $ROOTFS_IMG..."
    rm -rf "$EMPTY_ROOTFS_DIR"
    mkdir -p "$EMPTY_ROOTFS_DIR/Windows/System32"
    install_native_init_to_dir "$EMPTY_ROOTFS_DIR"
    build_rootfs_from_dir "$EMPTY_ROOTFS_DIR" "$ROOTFS_IMG"
end

# Create a temporary directory for the FAT-emulated Limine disk.
set -g EFI_ROOT "efi_root"
rm -rf "$EFI_ROOT"
mkdir -p "$EFI_ROOT/EFI/BOOT"
mkdir -p "$EFI_ROOT/boot/limine"

cp "$LIMINE_BOOT" "$EFI_ROOT/EFI/BOOT/$EFI_BOOT_FILE"
cp "$KERNEL_BIN" "$EFI_ROOT/kernel"

if test -z "$KERNEL_CMDLINE"
    set KERNEL_CMDLINE "root=$KERNEL_ROOT rootfstype=$KERNEL_ROOTFSTYPE"
    if test -n "$KERNEL_INIT"
        set KERNEL_CMDLINE "$KERNEL_CMDLINE init=$KERNEL_INIT"
    end
end

echo "timeout: 0
verbose: yes

/NT Kernel
    protocol: limine
    path: boot():/kernel
    cmdline: $KERNEL_CMDLINE" > "$EFI_ROOT/limine.conf"

cp "$EFI_ROOT/limine.conf" "$EFI_ROOT/boot/limine/limine.conf"
cp "$EFI_ROOT/limine.conf" "$EFI_ROOT/EFI/BOOT/limine.conf"

# Run in QEMU
echo "Running in QEMU (using Limine UEFI boot)..."
set -l qemu_args \
    $QEMU_OPTS \
    -smp 2 \
    -drive file=fat:rw:"$EFI_ROOT",format=raw \
    -drive if=none,id=drv0,file="$ROOTFS_IMG",format=raw \
    -device virtio-blk-pci,drive=drv0 \
    -serial stdio \
    -display none \
    -m 256M

if test "$ARCH" = "x86_64"; and test (uname) = "Linux"; and test -e /dev/kvm
    set qemu_args $qemu_args -accel kvm
end

$QEMU_BIN $qemu_args
