#!/bin/sh
# nxtsOS build: user program first, then freestanding 32-bit kernel + GRUB ISO.
# Log: logs/build.log
set -e
cd "$(dirname "$0")/.."
mkdir -p build logs build/iso/boot/grub
exec >logs/build.log 2>&1
echo "nxtsOS build started"
CFLAGS="-m32 -ffreestanding -O2 -Wall -Wextra -fno-stack-protector -fno-pic -fno-pie -no-pie -nostdlib"
echo "--- user program ---"
gcc $CFLAGS -c userland/test_prog.S -o build/user_start.o
gcc -m32 -ffreestanding -O0 -Wall -Wextra -fno-stack-protector -fno-pic -fno-pie -no-pie -nostdlib \
    -c userland/test_prog.c -o build/user_main.o
gcc -m32 -no-pie -Wl,--build-id=none -T userland/linker.ld -nostdlib \
    -o build/user_prog.elf build/user_start.o build/user_main.o
objcopy -O binary build/user_prog.elf build/user_prog.bin
ls -l build/user_prog.bin
echo "--- compiling kernel ---"
gcc $CFLAGS -c boot/boot.S -o build/boot.o
gcc $CFLAGS -c drivers/isr.S -o build/isr.o
gcc $CFLAGS -c drivers/gdt.S -o build/gdt_asm.o
gcc $CFLAGS -c kernel/switch.S -o build/switch.o
gcc $CFLAGS -c kernel/syscall.S -o build/syscall_asm.o
gcc $CFLAGS -c kernel/user_blob.S -o build/user_blob.o
for f in kernel/util.c kernel/console.c kernel/panic.c kernel/shell.c kernel/main.c \
         kernel/proc.c kernel/syscall.c \
         drivers/serial.c drivers/idt.c drivers/pic.c drivers/pit.c drivers/keyboard.c \
         drivers/gdt.c mm/pmm.c mm/vmm.c; do
    o="build/$(basename "$f" .c).o"
    echo "cc $f -> $o"
    gcc $CFLAGS -c "$f" -o "$o"
done
echo "--- linking ---"
# No -lgcc: the host has no 32-bit libgcc, and the kernel avoids runtime
# division calls (see util.c), so it links freestanding without it.
gcc -m32 -no-pie -Wl,--build-id=none -T boot/linker.ld -nostdlib -o build/nxtsOS.bin \
    build/boot.o build/isr.o build/gdt_asm.o build/switch.o build/syscall_asm.o \
    build/user_blob.o build/util.o build/console.o build/panic.o \
    build/shell.o build/main.o build/proc.o build/syscall.o build/serial.o build/idt.o \
    build/pic.o build/pit.o build/keyboard.o build/gdt.o build/pmm.o build/vmm.o
ls -l build/nxtsOS.bin
if command -v grub-file >/dev/null 2>&1; then
    grub-file --is-x86-multiboot build/nxtsOS.bin && echo "grub-file: multiboot OK"
fi
echo "--- ISO ---"
cp build/nxtsOS.bin build/iso/boot/nxtsOS.bin
cp config/vm/grub.cfg build/iso/boot/grub/grub.cfg
grub-mkrescue -o build/nxtsOS.iso build/iso
ls -l build/nxtsOS.iso
echo "BUILD OK"
