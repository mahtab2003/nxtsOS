# v0.7.2 security report (2026-10-27)

- Fixed LFB 0xE0000000: only reached after the Bochs VBE ID
  check passes (proving a Bochs VBE device is present), and the
  mapped framebuffer is verified by a write/read test pixel
  before any drawing (fb_verify in main.c). A wrong address
  fails verification and falls back to text mode; it does not
  corrupt memory. On real hardware without Bochs VBE, the ID
  check fails first, so the fixed address is never used.
- Keyboard polling: reads port 0x60 only when the controller
  status says output buffer full AND bit 5 clear (keyboard
  data). Mouse data is never consumed by polling, so mouse
  packets cannot be corrupted. Polling adds no new input
  source — it reads the same controller the IRQ handler reads.
- GRUB insmod vbe: tested, rejected (broken 1bpp mode in
  Bochs); not shipped.
- No exploitable findings in v0.7.2. GUI security test still
  PASS. Package signing, passphrase change/recovery,
  authenticated encryption remain unimplemented, as before.
