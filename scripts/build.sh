#!/bin/sh
# nxtsOS build: freestanding 32-bit kernel + GRUB ISO. Log: logs/build.log
set -e
cd "$(dirname "$0")/.."
mkdir -p build logs build/iso/boot/grub
exec >logs/build.log 2>&1
echo "nxtsOS build started"
CFLAGS="-m32 -ffreestanding -O2 -Wall -Wextra -fno-stack-protector -fno-pic -fno-pie -no-pie -nostdlib"
echo "--- compiling ---"
gcc $CFLAGS -c boot/boot.S -o build/boot.o
gcc $CFLAGS -c drivers/isr.S -o build/isr.o
for f in kernel/util.c kernel/console.c kernel/panic.c kernel/shell.c kernel/main.c \
         drivers/serial.c drivers/idt.c drivers/pic.c drivers/pit.c drivers/keyboard.c \
         mm/pmm.c; do
    o="build/$(basename "$f" .c).o"
    echo "cc $f -> $o"
    gcc $CFLAGS -c "$f" -o "$o"
done
echo "--- linking ---"
# No -lgcc: the host has no 32-bit libgcc, and the kernel avoids runtime
# division calls (see util.c), so it links freestanding without it.
gcc -m32 -no-pie -Wl,--build-id=none -T boot/linker.ld -nostdlib -o build/nxtsOS.bin \
    build/boot.o build/isr.o build/util.o build/console.o build/panic.o \
    build/shell.o build/main.o build/serial.o build/idt.o build/pic.o \
    build/pit.o build/keyboard.o build/pmm.o
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
