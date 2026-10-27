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
echo "--- disk-loadable ELF test programs (kept as ELF, not blobs) ---"
gcc -m32 -ffreestanding -O0 -Wall -Wextra -fno-stack-protector -fno-pic -fno-pie -no-pie -nostdlib \
    -c userland/hello.c -o build/hello_main.o
gcc -m32 -no-pie -Wl,--build-id=none -T userland/linker.ld -nostdlib \
    -o build/hello.elf build/user_start.o build/hello_main.o
gcc -m32 -ffreestanding -O0 -Wall -Wextra -fno-stack-protector -fno-pic -fno-pie -no-pie -nostdlib \
    -c userland/evil.c -o build/evil_main.o
gcc -m32 -no-pie -Wl,--build-id=none -T userland/linker.ld -nostdlib \
    -o build/evil.elf build/user_start.o build/evil_main.o
gcc -m32 -ffreestanding -O0 -Wall -Wextra -fno-stack-protector -fno-pic -fno-pie -no-pie -nostdlib \
    -c userland/slow.c -o build/slow_main.o
gcc -m32 -no-pie -Wl,--build-id=none -T userland/linker.ld -nostdlib \
    -o build/slow.elf build/user_start.o build/slow_main.o
gcc -m32 -ffreestanding -O0 -Wall -Wextra -fno-stack-protector -fno-pic -fno-pie -no-pie -nostdlib \
    -c userland/greet.c -o build/greet_main.o
gcc -m32 -no-pie -Wl,--build-id=none -T userland/linker.ld -nostdlib \
    -o build/greet.elf build/user_start.o build/greet_main.o
gcc -m32 -ffreestanding -O0 -Wall -Wextra -fno-stack-protector -fno-pic -fno-pie -no-pie -nostdlib \
    -c userland/hello2.c -o build/hello2_main.o
gcc -m32 -no-pie -Wl,--build-id=none -T userland/linker.ld -nostdlib \
    -o build/hello2.elf build/user_start.o build/hello2_main.o
gcc -m32 -ffreestanding -O0 -Wall -Wextra -fno-stack-protector -fno-pic -fno-pie -no-pie -nostdlib \
    -c userland/calc.c -o build/calc_main.o
gcc -m32 -no-pie -Wl,--build-id=none -T userland/linker.ld -nostdlib \
    -o build/calc.elf build/user_start.o build/calc_main.o
gcc -m32 -ffreestanding -O0 -Wall -Wextra -fno-stack-protector -fno-pic -fno-pie -no-pie -nostdlib \
    -c userland/guibad.c -o build/guibad_main.o
gcc -m32 -no-pie -Wl,--build-id=none -T userland/linker.ld -nostdlib \
    -o build/guibad.elf build/user_start.o build/guibad_main.o
gcc -m32 -ffreestanding -O0 -Wall -Wextra -fno-stack-protector -fno-pic -fno-pie -no-pie -nostdlib \
    -c userland/term.c -o build/term_main.o
gcc -m32 -no-pie -Wl,--build-id=none -T userland/linker.ld -nostdlib \
    -o build/term.elf build/user_start.o build/term_main.o
ls -l build/hello.elf build/evil.elf build/slow.elf build/greet.elf build/hello2.elf build/calc.elf build/term.elf build/guibad.elf
# Calculator package (Phase 8): installable from the shell with
# `pkg install calc.nxpkg` (the .nxpkg must not be pre-seeded as a
# plain calc.elf on the same disk, or the install is refused).
python3 tools/mkpkg.py build/calc.nxpkg --name calc --version 1.0 --file calc.elf:build/calc.elf
# Console package (Phase 10): same rule — do not pre-seed a plain
# term.elf on a disk that also carries term.nxpkg.
python3 tools/mkpkg.py build/term.nxpkg --name term --version 1.0 --file term.elf:build/term.elf
echo "--- version check ---"
# The kernel banner in main.c must match VERSION, or the bootloader
# bug from v0.3.0 (stale version in a hand-edited string) recurs.
grep -q "nxtsOS v$(cat VERSION)" kernel/main.c || { echo "version mismatch: kernel/main.c does not match VERSION"; exit 1; }
# Same guard for the desktop About window literal (Phase 8).
grep -q "nxtsOS v$(cat VERSION)" kernel/wm.c || { echo "version mismatch: kernel/wm.c About literal does not match VERSION"; exit 1; }
echo "--- compiling kernel ---"
gcc $CFLAGS -c boot/boot.S -o build/boot.o
gcc $CFLAGS -c drivers/isr.S -o build/isr.o
gcc $CFLAGS -c drivers/gdt.S -o build/gdt_asm.o
gcc $CFLAGS -c kernel/switch.S -o build/switch.o
gcc $CFLAGS -c kernel/syscall.S -o build/syscall_asm.o
gcc $CFLAGS -c kernel/user_blob.S -o build/user_blob.o
for f in kernel/util.c kernel/console.c kernel/panic.c kernel/shell.c kernel/main.c \
         kernel/proc.c kernel/syscall.c kernel/users.c kernel/elf.c kernel/sha256.c kernel/pkg.c kernel/aes.c kernel/enc.c kernel/fb.c kernel/wm.c \
         drivers/serial.c drivers/idt.c drivers/pic.c drivers/pit.c drivers/keyboard.c drivers/mouse.c \
         drivers/gdt.c drivers/ata.c fs/nxtsfs.c mm/pmm.c mm/vmm.c \
         net/e1000.c net/net.c net/tcp.c net/tls.c net/nettest.c net/bignum.c; do
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
    build/shell.o build/main.o build/proc.o build/syscall.o build/users.o build/elf.o build/sha256.o build/pkg.o build/aes.o build/enc.o build/fb.o build/wm.o build/serial.o build/idt.o \
    build/pic.o build/pit.o build/keyboard.o build/mouse.o build/gdt.o build/ata.o build/nxtsfs.o build/pmm.o build/vmm.o \
    build/e1000.o build/net.o build/tcp.o build/tls.o build/nettest.o build/bignum.o
ls -l build/nxtsOS.bin
if command -v grub-file >/dev/null 2>&1; then
    grub-file --is-x86-multiboot build/nxtsOS.bin && echo "grub-file: multiboot OK"
fi
echo "--- ISO ---"
cp build/nxtsOS.bin build/iso/boot/nxtsOS.bin
# Generate the GRUB menu from VERSION so the bootloader version can
# never go stale (v0.3.0's menu still said v0.2.0).
VER="$(cat VERSION)"
sed "s/@VERSION@/v$VER/g" config/vm/grub.cfg > build/iso/boot/grub/grub.cfg
grep "menuentry" build/iso/boot/grub/grub.cfg
grub-mkrescue -o build/nxtsOS.iso build/iso
ls -l build/nxtsOS.iso
echo "BUILD OK"
