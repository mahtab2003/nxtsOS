# v0.7.1 security report (2026-10-27)

- No new attack surface in the VBE fallback: it only runs when
  GRUB set no graphics mode, it never guesses a framebuffer
  address (PCI BAR of a class-0x03 device only, or it fails
  cleanly), it verifies the mapped framebuffer by a write/read
  test pixel before drawing, and it turns VBE off again on
  failure. IO port writes are to the standard Bochs VBE ports
  (0x1CE/0x1CF) and PCI config ports (0xCF8/0xCFC) only.
- Idle timeout change: default 120 minutes, user-settable 0-480
  minutes or off, per-session. Setting idle to 0 disables the
  idle lock for that session only — this is a deliberate user
  choice, not a bypass: the `lock` command and login still work,
  and the setting resets to 120 on reboot. A user who disables
  idle lock accepts that an unattended session stays unlocked.
- Keyboard flush: only on re-login and lock, never on first
  boot login (see TEST_REPORT.md for the regression this
  prevented). Flush discards keys, it never injects them.
- No exploitable findings in v0.7.1. Graphics/input security
  test (security_test_gui) still PASS. Package signing,
  passphrase change/recovery, authenticated encryption remain
  unimplemented, as in v0.7.0.
