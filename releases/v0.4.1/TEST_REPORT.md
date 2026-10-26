# v0.4.1 test report (QEMU 8.2.2, 2026-10-26)

Build PASS: kernel 35,972 bytes; ISO 5,158,912 bytes; Multiboot OK;
GRUB menu generated from VERSION shows v0.4.1; kernel banner v0.4.1.

- tests/qemu_test_v041.py PASS at 128 MB: login as user, runbg slow.elf
  (pid 10, uid 1000), jobs shows it active, kill 10, jobs empty,
  lock + wrong password logs out, re-login as user, 30 s idle then
  whoami still works (no early idle lock), logout. Note: background
  output interleaves with typed input on screen (documented limit);
  the typed commands themselves are received correctly.
- tests/qemu_test_phase5.py PASS at 128 MB (regression): user secret
  denied, root secret read, audit log correct, user-denied-before-root-read YES.
- tests/qemu_test.py PASS at 128 MB (base, no disk, root setup mode).
- tests/qemu_test_storage.py PASS at 32 MB: write -> reboot -> read back.
- Startup test timing: P1/P2 now time-based (P2 busy-waits 30 ticks per
  iteration), total ~1.5 s on any host, with P1 iter 1/2/3 printing during
  P2's busy loop (timer-preemption proof preserved). Previously: 50M
  iterations x 5 took tens of seconds on a slow host; 5M iterations
  finished under one 100 ms quantum on a fast host and proved nothing.
  Both of those were measured in QEMU and fixed here.

NOT QEMU-tested (honest): the 30-minute idle timeout trigger itself
(waiting 30 minutes in a test is not feasible). The lock/unlock code
path is tested via `lock`, and a 30-second idle test proves no early lock.
