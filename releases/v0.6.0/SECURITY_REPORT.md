# v0.6.0 security report (adversarial test, 2026-10-26)

- tests/security_test_enc.py PASS (see TEST_REPORT.md for the full
  list: raw hiding, superblock tamper, header tamper, package tamper
  on an encrypted disk). No exploitable findings in the encryption
  code; no post-test kernel fix was required.
- Two test-development fixes, not kernel fixes: (1) the first
  package-install test failed because the test disk contained both
  a loose hello.elf and hello.nxpkg — the installer correctly
  refused to overwrite a loose file, the disk was fixed; (2) the
  first superblock-tamper test flipped a reserved superblock byte
  (offset 100), which correctly does not affect mounting — the test
  was fixed to flip the magic byte, which correctly fails mounting.
- Known gaps, stated not hidden (see docs/ENCRYPTION.md):
  no passphrase change, no recovery key, no authenticated
  encryption (CTR = confidentiality only), offline brute force
  limited by the 10000-round work factor only, so a weak passphrase
  is guessable. Package signing is still not implemented.
