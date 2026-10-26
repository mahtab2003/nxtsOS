# Build and Test

## Build

```sh
./scripts/build.sh        # produces build/nxtsOS.iso and build/nxtsOS.bin
```

Steps inside `build.sh`: assemble `boot/boot.S`, compile every `.c` with
`gcc -m32 -ffreestanding -nostdlib -fno-builtin -Wall -Wextra`, link with
`boot/linker.ld`, check the Multiboot header with `grub-file` (when present),
assemble the ISO with `grub-mkrescue`.

Build log: `logs/build.log` (overwritten each build).

## Test

```sh
./scripts/test_boot.sh    # boots the ISO in QEMU, headless, serial-captured
python3 tests/unicorn_boot.py build/nxtsOS.bin   # CPU-emulator boot test
```

The test boots with `-m 128 -display none -serial file:logs/serial.log
-monitor none`, waits, then checks `logs/serial.log` for the exact markers:

- `nxtsOS kernel starting`
- `PMM:`
- `Interrupts enabled`
- `nxts> ` (shell prompt)

It also runs `tests/check_source.py`, which asserts the source tree contains
the documented modules and no build artefacts are packaged as source.

Graphical (VGA) verification is separate: `scripts/run_qemu.sh` opens a
window; `tests/screendump.sh` uses the QEMU monitor to capture a PPM
screenshot of the VGA display for manual inspection. A screenshot is
evidence only when it is actually captured from that run — see
`releases/v0.1.0/TEST_REPORT.md` for what was captured for v0.1.0.

## What "verified" means here

A release is verified only for the checks listed as PASS in its test report,
with the exact QEMU command line recorded. Anything else is NOT TESTED or
NOT IMPLEMENTED, and is listed as such.
