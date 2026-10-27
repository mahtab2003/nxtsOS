# nxtsOS v0.7.3 — Security Report (adversarial review)

Method: third-party-style review of the changed code, plus the
existing regression suites (GUI security, encryption, package).

## Changes reviewed

- PS/2 controller init (keyboard.c): all controller waits are
  bounded (100,000 iterations), all drains are bounded (32
  bytes). A controller that never answers cannot hang boot:
  init aborts that step and boot continues with BIOS defaults,
  i.e. no worse than v0.7.2. No new input source is added:
  polling reads only the controller output buffer, the same
  bytes IRQ handlers already read. Scancode set 2 + translation
  on is the BIOS standard configuration; forcing it cannot
  enable a new attack surface, it only makes the scancode set
  consistent with the driver's set-1 tables.
- Polling mouse bytes: a stale mouse byte fed by polling can
  cause at most one spurious mouse packet (see mouse resync
  fix); it cannot inject keyboard characters, because mouse
  bytes are never fed to the keyboard buffer (status bit 5
  routing is preserved, only the skip is replaced by a feed
  to the mouse driver).
- Mouse resync: discarding bit-3-clear first bytes cannot drop
  a valid packet (valid first bytes always have bit 3 set
  by the PS/2 spec), and test_set resetting the packet index
  only affects test harnesses, not real input.

## Findings

- No exploitable findings in the v0.7.3 changes. The lodged-byte
  condition itself was a denial-of-service on input (keyboard
  dead until reboot, and a reboot with the same GRUB key timing
  could repeat it) — fixed by the init drain, not by masking it.
- Unchanged limits (from earlier reports): no package signing,
  CTR encryption is confidentiality-only, password KDF is not
  memory-hard, no passphrase change/recovery. None are introduced
  or worsened by v0.7.3.
