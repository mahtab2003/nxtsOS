# nxtsOS v0.3.0 — Test Report

## Test 1: Build — PASS

- Command: `./scripts/build.sh`. Kernel 24,684 bytes, ISO 5,148,672 bytes.
- `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK.
- Note: during this build the sandbox had lost grub-mkrescue/xorriso
  (VM replacement); they were reinstalled via apt and the build then
  succeeded. QEMU 8.2.2 was already present.

## Test 2: Persistence, 128 MB — PASS

- Command: `python3 tests/qemu_test_storage.py build/nxtsOS.iso 128
  /tmp/serial-storage.log /tmp/mon-storage.sock /tmp/test-disk.img`
- Result: PASS. Serial log shows `Filesystem mounted` (nxtsFS v1,
  32,768 sectors, 32,754 free), seeded `hello.txt` readable, `Wrote
  persist.txt`, guest reboot, second boot, `cat persist.txt` →
  `hello-persist`, `ls` shows both files (18 and 13 bytes, mode 420).
  The read-back was verified to occur after the second boot banner,
  not before it.

## Test 3: Persistence, 64 MB — PASS

- Same command with RAM 64. Result: PASS, same markers, read-back
  after reboot: YES.

## Test 4: Base regression (no disk), 128 MB — PASS

- Command: `python3 tests/qemu_test.py build/nxtsOS.iso 128
  /tmp/serial-base.log /tmp/mon-base.sock`
- Result: PASS. All markers found, including the updated help text.
  PMM used after processes = 288 frames (post-paging baseline — no leak).

## Test 5: Adversarial security tests — PASS (see SECURITY_REPORT.md)

- Command: `python3 tests/security_test_storage.py build/nxtsOS.iso
  build/nxtsOS-disk.img /tmp/sec-storage`
- Result: PASS, 8/8 cases (7 corrupt disk images + 1 too-long filename).
  One real finding (huge total_sectors → free-space scan denial of
  service) was found during this work, fixed, and retested to PASS.

## NOT TESTED

- VirtualBox (QEMU is the supported path).
- Real hardware.
- A disk larger than 16 MiB (layout supports up to 32,768 sectors with
  the current 8-sector bitmap; larger disks need a larger bitmap, which
  is a Phase 5/6 extension, not a claim made here).
- Write of a file larger than free space via the shell: the shell line
  is 128 chars, so it cannot trigger that path; the allocation check
  is in code (new blocks are allocated before old blocks are freed, and
  failure keeps the old file) and the same bounds logic is exercised by
  the corrupt-disk cases. This is stated honestly, not claimed as tested.
