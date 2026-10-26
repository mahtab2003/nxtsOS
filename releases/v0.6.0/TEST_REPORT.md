# v0.6.0 test report (QEMU 8.2.2, 2026-10-26)

Build PASS: kernel 51,560 bytes; ISO 5,175,296 bytes; Multiboot OK;
GRUB menu generated from VERSION shows v0.6.0; kernel banner v0.6.0;
build.sh now fails if the banner does not match VERSION.

- tests/qemu_test_enc.py PASS: Boot 1 (correct passphrase "diskpass",
  on a fresh encrypted disk): Disk unlocked, AES-256-CTR enabled,
  Filesystem mounted, login as user, public read, secret denied,
  logout, login as root, pkg install hello 1.0, pkg list, run
  hello.elf works — package install on an encrypted disk works.
  Boot 2 (wrong passphrase x3): "Too many failed attempts. System
  halted.", no unlock, no FS, no shell prompt.
  Boot 3 (no disk): `aes-test` prints 8ea2b7ca...60089, "AES test PASS"
  (FIPS 197 AES-256 vector, independent of any disk).
  Note: the test disk is recreated fresh before each run, because
  Boot 1 installs a package and mutates the disk in place.
- tests/security_test_enc.py PASS: raw disk hides "top secret",
  "public data", "Hello from ELF" (all present in the plain disk);
  superblock tamper (encrypted magic byte flipped): disk unlocks,
  FS mount fails cleanly ("no valid nxtsFS"), no users loaded;
  header tamper (key-check flipped): correct passphrase fails three
  times, system halts, no unlock, no FS; package tamper on an
  encrypted disk (installed hello.elf's encrypted sector flipped,
  sector found by host-decrypting the disk with OpenSSL): FS mounts,
  `run hello.elf` refused ("cannot run hello.elf"), pkg list still
  shows hello 1.0.
- Regressions PASS: tests/qemu_test_pkg.py, tests/qemu_test_phase5.py,
  tests/security_test_phase5.py 3/3, tests/qemu_test_v041.py,
  tests/qemu_test.py (base, 128 MB), tests/qemu_test_storage.py
  (32 MB, write -> reboot -> read back).
