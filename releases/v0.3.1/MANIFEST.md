# nxtsOS v0.3.1 — Release Manifest (bugfix on v0.3.0)

- Version: 0.3.1 (Phase 4 bugfix, no new phase)
- Kernel binary: `build/nxtsOS.bin` (24,896 bytes)
- Bootable image: `build/nxtsOS.iso` (5,148,672 bytes, El Torito via grub-mkrescue)
- Build command: `./scripts/build.sh`
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Git tag: `v0.3.1` (local repository only)
- Source archive: `archives/code/nxtsOS-v0.3.1-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.3.1-dist.zip`
- Checksums: `releases/v0.3.1/SHA256SUMS`

## What was wrong (user-reported, with screenshot)

1. The GRUB bootloader menu in the v0.3.0 ISO still said "nxtsOS
   v0.2.0", even though the kernel printed v0.3.0. Root cause:
   `config/vm/grub.cfg` was hand-edited and never updated when the
   version bumped; the build script copied it verbatim.
2. The screenshot showed only the `P1 iter` / `P2 iter` lines and no
   command prompt. Root cause (not a hang): the two built-in test
   programs run *before* the shell, and nothing on screen said a prompt
   was coming — so their output looked like a stuck test run. The
   prompt does appear after they finish (verified at 32 MB, the
   configuration in the screenshot, and at 128 MB).

## Fixes in v0.3.1

- `scripts/build.sh` now generates the GRUB menu from the `VERSION`
  file, so the bootloader version can never go stale again. Verified:
  the `grub.cfg` extracted from the built ISO says
  `menuentry "nxtsOS v0.3.1"` and contains no "0.2.0".
- The kernel now prints, before the test programs,
  "Starting built-in test programs (2 processes)..." and
  "The nxts> shell prompt will appear when they finish; keys typed
  now are buffered.", and after them "Test programs finished.
  Starting shell...". Keys typed during the test programs were already
  buffered by the keyboard driver (256-char ring) and are not lost.
- `README.md` updated from its stale v0.2.0 text to v0.3.1 (it still
  claimed no filesystem and no user processes, both implemented in
  v0.2.0/v0.3.0), and `docs/VM_GUIDE.md` now explains the wait for the
  prompt.

## NOT changed

No new features, no filesystem/driver changes, no new attack surface.
The security properties of v0.3.0 are unchanged; see
`releases/v0.3.0/SECURITY_REPORT.md`.

## Remote publishing

NOT DONE. No authorised git-host account access to mahtab2003/nxtsOS
has been granted yet (Muse GitHub App repository selection pending).
See the main-chat notes for that step.
