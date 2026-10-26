# nxtsOS v0.5.0 — Release Manifest (Phase 6 — Package management)

- Version: 0.5.0 (Phase 6)
- Kernel binary: `build/nxtsOS.bin` (48,164 bytes)
- Bootable image: `build/nxtsOS.iso` (5,171,200 bytes, El Torito via grub-mkrescue)
- Build command: `./scripts/build.sh`
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Git tag: `v0.5.0` (local repository only)
- Source archive: `archives/code/nxtsOS-v0.5.0-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.5.0-dist.zip`
- Checksums: `releases/v0.5.0/SHA256SUMS`

## Implemented (v0.5.0)

- NXPKG package format (docs/PACKAGES.md), host tool tools/mkpkg.py,
  kernel SHA-256, strict manifest parsing, installer with dependency
  version operators (>=, ==), duplicate/upgrade handling, removal
  protection (+force with warning), root-only install/remove,
  root-only registry packages.txt, load-time SHA-256 verification
  in the ELF loader, shell commands `pkg list/install/remove` and
  `sha256 <file>`, test programs greet.elf and hello2.elf.

## NOT implemented (explicit)

Package signing, disk encryption (next, as a dedicated phase),
graphics, desktop, networking. See docs/ROADMAP.md and
releases/v0.5.0/SECURITY_REPORT.md.

## Remote publishing

NOT DONE. Muse GitHub App repository selection for mahtab2003/nxtsOS
is still pending; no push has been made.
