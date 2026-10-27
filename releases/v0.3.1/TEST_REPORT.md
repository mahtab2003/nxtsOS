# nxtsOS v0.3.1 — Test Report

## Test 1: Build + bootloader version inside the ISO — PASS

- Command: `./scripts/build.sh`. Kernel 24,896 bytes, ISO 5,148,672 bytes.
- `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK.
- `grub.cfg` extracted from the built ISO with xorriso:
  `menuentry "nxtsOS v0.3.1"`, and zero occurrences of "0.2.0".
  This is the exact check that would have caught the v0.3.0 bug.

## Test 2: Persistence at 32 MB (the configuration in the user's screenshot) — PASS

- Command: `python3 tests/qemu_test_storage.py build/nxtsOS.iso 32
  /tmp/serial-32b.log /tmp/mon-32b.sock /tmp/test-disk32b.img`
- Result: PASS. Serial log shows `Filesystem mounted`, seeded
  `hello.txt` readable, `Wrote persist.txt`, guest reboot, second boot,
  `cat persist.txt` → `hello-persist`, `ls` shows both files, and the
  new messages "Starting built-in test programs..." /
  "The nxts> shell prompt will appear when they finish..." /
  "Test programs finished. Starting shell..." appear on both boots,
  followed by the `nxts> ` prompt.

## Test 3: Base regression at 128 MB — PASS

- Command: `python3 tests/qemu_test.py build/nxtsOS.iso 128
  /tmp/serial-base31.log /tmp/mon-base31.sock`
- Result: PASS, all markers found, shell prompt works.

## NOT TESTED

- VirtualBox, real hardware (QEMU is the supported path).
- The GRUB menu visually (VGA only, 2-second timeout, default entry
  boots automatically) — verified by extracting `grub.cfg` from the
  ISO, which is the file GRUB reads.
