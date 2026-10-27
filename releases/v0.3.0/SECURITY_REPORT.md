# nxtsOS v0.3.0 — Adversarial Security Report

Method: `docs/SECURITY_TESTING.md`. Attacker view for this release: a
malicious or corrupt disk image is untrusted input, and so is any
filename typed at the shell. The tester did not trust the filesystem
code it was testing.

## Cases run (all in QEMU, QEMU 8.2.2)

| # | Case | Result |
|---|---|---|
| 1 | Superblock magic zeroed (`XXXXXXXX`) | PASS — mount refused cleanly, shell works, no panic |
| 2 | Total sectors = 0xFFFFFFFF | PASS after fix (see Finding 1) |
| 3 | Data start sector = 0 (overlaps superblock) | PASS — mount refused, shell works |
| 4 | Directory entry start sector = 999,999, count 10 | PASS — entry skipped with warning, shell works |
| 5 | Directory entry size = 0xFFFFFF00 | PASS — entry skipped, shell works |
| 6 | Directory entry name = 32 `A`s, no NUL terminator | PASS — entry skipped, shell works |
| 7 | Directory entry mode = 0xFFFFFFFF | PASS — entry skipped, shell works |
| 8 | Shell filename of 40 chars (> 31 limit) | PASS — `write` refused with "cannot write", shell works |

In every case: exactly 1 boot (no reboot loop), no `KERNEL PANIC`,
no exception, no page fault, and the shell prompt appeared.

## Finding 1 — FIXED (denial of service, corrupt superblock)

- **Found by:** case 2, during code review before the test run.
- **Bug:** `fs_mount` accepted any total_sectors up to 1,000,000, but
  `fs_status` (called at boot) scans every sector from data_start to
  total_sectors to count free space. A disk claiming 0xFFFFFFFF sectors
  would make that scan loop for billions of iterations — effectively a
  hang from a corrupt disk image.
- **Fix:** mount now rejects a superblock whose total_sectors is not
  covered by its own bitmap (`total > bitmap_sectors * 4096`, or
  `total <= (bitmap_sectors - 1) * 4096`). With the 8-sector bitmap
  cap, the scan is bounded to 32,768 sectors. The fix was rebuilt and
  case 2 re-run to PASS.
- **Lesson carried forward:** every loop over an on-disk count must
  have a bound derived from a validated, independently checked value —
  not from the untrusted count itself.

## Known limitations (not exploitable in this release, recorded honestly)

- File owner/mode are recorded but not enforced for non-root users,
  because there are no users yet (Phase 5). This is not exploitable in
  v0.3.0: filesystem access exists only via the kernel shell (trusted,
  UID 0); user processes have no filesystem syscalls in this release.
  Enforcement lands with users/sessions in Phase 5 and will be
  adversarially tested there.
- A failed `fs_write` after some data sectors were written leaves
  orphaned data in sectors that are still marked free on disk. Those
  sectors are not referenced by any directory entry and cannot be read
  through the filesystem; they will be reused by a later allocation.
  This is a hygiene note, not a data leak through any API.
- Write-larger-than-free-space via the shell is not QEMU-triggerable
  (128-char shell line); see TEST_REPORT.md, "NOT TESTED".
