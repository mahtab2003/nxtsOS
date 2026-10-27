# v0.5.0 test report (QEMU 8.2.2, 2026-10-26)

Build PASS: kernel 48,164 bytes; ISO 5,171,200 bytes; Multiboot OK;
GRUB menu generated from VERSION shows v0.5.0; kernel banner v0.5.0.

- tests/qemu_test_pkg.py PASS at 128 MB (setup mode, root): SHA-256
  vector sha256("abc") = ba7816bf...15ad exactly; greet install
  refused before hello (missing dependency); hello 1.0 installed;
  greet 1.0 (depends hello>=1.0) installed; duplicate hello 1.0
  refused; pkg list shows both; run hello.elf and greet.elf work;
  remove hello refused while greet depends on it; remove greet,
  remove hello, pkg list empty; reinstall hello 1.0, upgrade to
  1.1, pkg list shows 1.1, run hello.elf prints "Hello v1.1".
- Root-only check PASS: as user, `pkg install` prints "root only"
  and `pkg list` shows no packages installed.
- Regressions PASS: tests/qemu_test_phase5.py (Phase 5 end-to-end),
  tests/security_test_phase5.py 3/3 boots, tests/qemu_test.py (base,
  128 MB), tests/qemu_test_storage.py (32 MB, write -> reboot ->
  read back).
