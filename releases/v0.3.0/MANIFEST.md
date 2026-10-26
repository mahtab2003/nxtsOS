# nxtsOS v0.3.0 — Release Manifest

- Version: 0.3.0 (Phase 4 — Persistent storage)
- Project location: `~/workspace/nxtsOS`
- Kernel binary: `build/nxtsOS.bin` (24,684 bytes)
- Bootable image: `build/nxtsOS.iso` (5,148,672 bytes, El Torito via grub-mkrescue)
- Disk image: `build/nxtsOS-disk.img` (16 MiB nxtsFS, seeded with `hello.txt`)
- Build command: `./scripts/build.sh` (log: `logs/build.log`)
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Git tag: `v0.3.0` (local repository only)
- Source archive: `archives/code/nxtsOS-v0.3.0-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.3.0-dist.zip`
- Checksums: `releases/v0.3.0/SHA256SUMS` (also inside the dist zip)

## Implemented (v0.3.0)

Everything in v0.2.0, plus:

- ATA PIO driver (primary IDE, master, LBA28, sector read/write, cache
  flush, timeout on every wait — a missing/faulty disk returns an error,
  never hangs the kernel).
- VFS API (`fs/vfs.h`) with nxtsFS as the first backend, documented in
  `docs/FILESYSTEM.md`: superblock, sector bitmap, fixed root directory
  (32 entries), contiguous file allocation, owner UID + mode recorded
  on every file.
- Shell file commands: `fs`, `ls`, `cat <file>`, `write <file> <text>`,
  `rm <file>`, with argument parsing.
- Host disk tool `tools/mkdisk.py` (formats a disk image, optionally
  seeds files). The kernel never formats a disk on its own.
- Process teardown: exited processes' page directories, page tables,
  code frames, and stack frames are freed (fixes the v0.2.0 leak).
  After two test processes, PMM used = 288 frames, which is exactly the
  post-paging baseline (279 at PMM print + 9 for the kernel PD/PTs) —
  zero leaked frames.
- Full task plan rewritten core-first (`docs/ROADMAP.md`) with a
  per-release adversarial security test (`docs/SECURITY_TESTING.md`).

## NOT implemented (explicit)

Graphical desktop/window manager, GUI applications, ELF loader from
disk, users/login/sessions (so file permission *enforcement* for
non-root users does not exist yet — see VM_GUIDE known issues),
package management, networking, mouse, UEFI. See `docs/ROADMAP.md`.

## Remote publishing

NOT DONE. No authorised git-host account was connected, so nothing was
pushed. To publish later:

```sh
git remote add origin <your-new-private-repo-url>
git push -u origin main
git push origin v0.3.0
```

Prefer private initially; make public only with explicit authorisation.
