# nxtsOS v0.10.0 — Test Report

Kernel: build/nxtsOS.bin (173,264 bytes). ISO: build/nxtsOS.iso
(5,296,128 bytes, sha256 in SHA256SUMS and in the
distribution zip's internal SHA256SUMS). All tests run
2026-10-27 on this exact ISO, QEMU 8.2.2 and Bochs 2.7 in
sandbox. No kernel source changed between the tested ISO
and the packaged ISO (only test-script and documentation
changes after the final build, plus the release docs
themselves).

## QEMU PASS — new in v0.10.0

- tests/qemu_test_desktop10.py (mode 4, no disk):
  "Desktop theme changed to Dark", WS2 pixel 0x101010
  (dark desktop bg, Settings hidden), WS1 pixel
  0xD0D0D0 (Settings client grey), snapped x=0 w=400,
  restored x=160 w=480 — RESULT PASS. (One early run
  failed only on the test's own expectation string:
  the kernel prints uppercase hex 0xD0D0D0, the test
  expected lowercase. Test fixed, kernel untouched.)
- tests/qemu_test_desktop_apps.py (mode 5, setup disk:
  notes.txt, pic.bmp 64×64, calc.nxpkg, term.nxpkg):
  boot 1 installs calc 1.0 + term 1.0; boot 2
  "Console started", "term: window opened",
  "editor: opened notes.txt", "viewer: opened pic.bmp
  64x64" — RESULT PASS. Files row order (notes row 0,
  pic row 1) confirmed by the markers.
- tests/security_test_desktop10.py (mode 6, setup disk:
  evil.txt, empty.txt, big.bmp 200×200 header with no
  pixels, good.bmp 64×64, garbage settings.txt):
  "settings: ignored invalid theme=99",
  "settings: ignored invalid wallpaper=5",
  "editor: sanitized 4 bytes in evil.txt",
  "editor: opened evil.txt", "editor: opened empty.txt
  0 bytes", "viewer: refused big.bmp (oversize 200x200,
  cap 128x128)", "viewer: opened good.bmp 64x64" —
  RESULT PASS.
- tests/qemu_test_desktop_web.py (mode 7, slirp, host
  server on 127.0.0.1:18081 serving a 20000-byte page):
  "DHCP ok ip=10.0.2.15", "web: truncated at 8192" —
  RESULT PASS. (First run failed: see the truncation
  bug in SECURITY_REPORT.md. Shell-level confirmation
  after the fix: "http: 8076 bytes (truncated)".)
- tests/qemu_test_desktop_nonic.py (mode 8, `-nic
  none`): "network: no device" — RESULT PASS.

## QEMU PASS — regressions (unchanged behaviour)

- tests/qemu_test.py (base, 128 MB): all markers — PASS.
- tests/qemu_test_v071.py: fbinfo, guitest, mousetest,
  wmautotest, idle 120/5/off/120, logout, mem — PASS.
- tests/security_test_gui.py: screendump counts
  identical to v0.7.0–0.7.4 (teal 215200 / blue 5798 /
  white 9671 / cursor (400,300) white) — PASS. The
  Classic theme reproduces the v0.8.0/v0.9.0 pixels
  exactly.
- tests/qemu_test_desktop.py: cliptest, cursortest,
  desktopautotest, desktop screendump pixels — PASS.
  (A regression was caught and fixed during this
  release: the new max_step chain gave mode 1 a max
  step of 3 instead of 11, so the classic script died
  after opening Settings. Fixed to 11 for mode 1 and
  3 for mode 8; see SECURITY_REPORT.md.)
- tests/qemu_test_calc.py (fresh setup disk):
  install calc, "Calculator started", title bar blue,
  display white, key grey, display glyph '7' — PASS.
- tests/security_test_desktop.py (fresh setup disk):
  non-admin save denied, lock held after wrong
  password, guibad PASS, tampered calc refused — PASS.
- tests/qemu_test_pkg.py (fresh disk: abc.txt, hello /
  greet / hello-1.1 packages): SHA-256 abc vector,
  install/list/remove, dependency order, duplicate
  install, upgrade hello 1.0 → 1.1 "Hello v1.1" — PASS.
  (First run failed only because the hand-built
  hello11 package contained the 1.0 binary instead of
  hello2.elf — a disk-recipe error, not a kernel
  regression; rebuilt with hello2.elf and passed.)
- tests/qemu_test_enc.py (fresh encrypted disk,
  passphrase diskpass): correct-passphrase boot
  (public read, secret denied, install + run hello),
  wrong passphrase ×3 → halt, aes-test vector
  8ea2b7ca… + "AES test PASS" — PASS. (First run
  failed only because the hand-built disk pre-seeded
  a plain hello.elf, which the installer correctly
  refuses as "file already exists on disk" — a
  disk-recipe error; rebuilt without it and passed.)
- tests/security_test_pkg.py (setup disk with 12
  malicious packages): bad hash, bad size, path
  traversal, absolute path, self-dependency,
  dependency cycle, conflicting dependency, oversize
  packages all refused; good packages install — PASS.
- tests/qemu_test_net.py (slirp): e1000, DHCP
  ip=10.0.2.15, ping reply, nettest PASS — RESULT
  PASS (slirp DNS + real-internet fetch bonus-only,
  unchanged environment limit).
- tests/qemu_test_net_peer.py (deterministic socket
  peer harness): DHCP, ping, DNS, local HTTP, nettest
  — RESULT PASS.
- tests/qemu_test_tls.py (python ssl server): TLS 1.2
  handshake + fetch — RESULT PASS.
- tests/security_test_net.py: 400-frame flood → ping
  + netinfo alive, out-of-bounds DNS pointer → clean
  failure, wrong-host/tampered/expired certs refused
  exactly 3 times, plain-HTTP on TLS port fails —
  RESULT PASS. (The first invocation of this suite
  in the regression run printed no verdict through
  the grep pipeline; the clean rerun passed fully.)

## Bochs PASS

- Recreated harness /tmp/boch080.py (Xvfb + SDL2 +
  xdotool, shipped bochsrc.txt, current ISO): guitest
  PASS, desktopautotest PASS. (First run failed only
  because the VM replacement had removed xdotool's
  libXtst.so.6, so no keystroke ever reached the
  guest — restored from the apt cache and passed.
  The guest also runs its clock ~30× fast under this
  Bochs config, which tripped the 120-minute idle
  lock during the failed run's long waits; that is a
  Bochs timing quirk, not a kernel defect.)

## Notes on flakes (recorded honestly)

- QEMU monitor sendkey occasionally delivers a doubled
  key ("desktoop10test", "desktop10testt", earlier
  "ggui"). The five new harnesses retry a command once
  when the shell reports `Unknown command` (checking
  only the fresh log portion); the classic suites
  predate this and were rerun on flakes instead.
- The sandbox VM was replaced twice mid-session
  (QEMU, GRUB, xorriso, Bochs, xdotool vanished);
  all were restored from /var/cache/apt/archives —
  see AGENTS.md for the dependency chains. No test
  result above comes from a run with missing tools.
