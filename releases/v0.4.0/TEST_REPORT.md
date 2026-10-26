# nxtsOS v0.4.0 — Test Report

## Test 1: Build — PASS

- Command: `./scripts/build.sh`. Kernel 31,956 bytes, ISO 5,154,816 bytes.
- `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK.
- Disk-loadable ELFs built: `build/hello.elf` (6,208 bytes),
  `build/evil.elf` (5,804 bytes).

## Test 2: Phase 5 end-to-end, 128 MB — PASS

- Command: `python3 tests/qemu_test_phase5.py build/nxtsOS.iso 128
  /tmp/serial-p5.log /tmp/mon-p5.sock /tmp/p5-test.img`
  (disk seeded with hello.elf, users.txt root/user, secret.txt mode
  0600, public.txt mode 0644)
- Result: PASS, all 16 markers, in order where order matters:
  login as user, `whoami` → "user uid 1000", `cat secret.txt` refused,
  `cat public.txt` → "public data", `run hello.elf` → "Hello from ELF",
  "uid: 1000", "secret: access denied", "elf write ok",
  "Program hello.elf finished", logout, login as root,
  `cat secret.txt` → "top secret", `run hello.elf` as root →
  "uid: 0" and "secret: top secret", `cat audit.log` →
  "login-ok user", "logout user", "login-ok root".

## Test 3: Phase 5, 64 MB — PASS

- Same test with RAM 64. Result: PASS, same markers.

## Test 4: Base regression, no disk, 128 MB — PASS

- Command: `python3 tests/qemu_test.py build/nxtsOS.iso 128 ...`
- Result: PASS. Without a users file the system boots as root in
  setup mode with a warning, and the prompt is `root@nxts> `.

## Test 5: Storage regression, 32 MB — PASS

- Command: `python3 tests/qemu_test_storage.py build/nxtsOS.iso 32 ...`
  (disk with hello.txt only, no users file → root fallback)
- Result: PASS, file written before reboot read back after reboot.

## Test 6: Adversarial security tests — PASS (see SECURITY_REPORT.md)

- Commands: `python3 tests/security_test_phase5_setup.py /tmp/sec5`
  then `python3 tests/security_test_phase5.py build/nxtsOS.iso /tmp/sec5`
- Result: PASS, 3/3 boots (8 malformed ELFs + evil ELF, brute force,
  malformed users line).

## NOT TESTED

- Idle session lock timeout (10 minutes): not feasible in a QEMU test
  run; tick comparison reviewed, lock path documented as untested in
  docs/SECURITY.md and here.
- VirtualBox, real hardware (QEMU is the supported path).
- A disk larger than 16 MiB, or an ELF larger than 64 KiB (loader cap;
  larger programs are rejected, not claimed to load).
