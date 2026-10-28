# Build and Test

## Build

```sh
./scripts/build.sh        # produces build/nxtsOS.iso and build/nxtsOS.bin
```

Steps inside `build.sh`: assemble `boot/boot.S`, compile every kernel `.c`
with `gcc -m32 -ffreestanding -O2 -Wall -Wextra -fno-stack-protector
-fno-pic -fno-pie -no-pie -nostdlib` (the userland test programs use
`-O0` with the same freestanding flags), link with `boot/linker.ld`,
check the Multiboot header with `grub-file` (when present),
assemble the ISO with `grub-mkrescue`.

CORRECTION: this paragraph used to state the kernel flags as
`gcc -m32 -ffreestanding -nostdlib -fno-builtin -Wall -Wextra`.
There is no `-fno-builtin` in `scripts/build.sh` (its kernel `CFLAGS`
line carries `-O2` and the `-fno-stack-protector -fno-pic -fno-pie
-no-pie` set instead); the flag line above now matches that line.

Build log: `logs/build.log` (overwritten each build).

## Test

```sh
./scripts/test_boot.sh    # boots the ISO in QEMU, headless, serial-captured
python3 tests/unicorn_boot.py build/nxtsOS.bin   # CPU-emulator boot test
```

`test_boot.sh` runs `python3 tests/qemu_test.py build/nxtsOS.iso 128
logs/serial.log /tmp/nxts-mon.sock`. That harness boots with `-m 128
-display none -serial file:logs/serial.log -monitor
unix:/tmp/nxts-mon.sock,server,nowait`, waits for the shell prompt,
then types `help` and `mem` through the monitor (`sendkey`) and
checks `logs/serial.log` for the exact markers:

- `nxtsOS kernel starting`
- `PMM:`
- `GDT installed`
- `Interrupts enabled`
- `nxts> ` (shell prompt)
- `Commands: help, mem, ticks, clear, reboot`
- `Memory: total`

CORRECTION: this section used to say the test boots with
`-monitor none`, waits, then checks four markers. There is no
`-monitor none` run: the harness needs the monitor socket to type
the `help`/`mem` commands, and it checks seven markers, not four
(the `GDT installed`, `Commands: …`, and `Memory: total` lines
were missing from the old list).

It also runs `tests/check_source.py`, which asserts the source tree contains
the documented modules and no build artefacts are packaged as source.

Graphical (VGA) verification is separate: `scripts/run_qemu.sh` opens a
window; the QEMU monitor's `screendump` command — sent by the test
harnesses (`tests/qemu_test_desktop.py`, `tests/qemu_test_calc.py`)
over the monitor socket — captures a PPM screenshot of the display
for pixel analysis. A screenshot is evidence only when it is actually
captured from that run — see `releases/v0.1.0/TEST_REPORT.md` for
what was captured for v0.1.0.

CORRECTION: this paragraph used to name `tests/screendump.sh` as
the capture tool. No such file exists anywhere in the tree — the
only reference to it was this paragraph itself. Screendump capture
has always been a monitor command issued by the harnesses, as
stated above.

## What "verified" means here

A release is verified only for the checks listed as PASS in its test report,
with the exact QEMU command line recorded. Anything else is NOT TESTED or
NOT IMPLEMENTED, and is listed as such.
