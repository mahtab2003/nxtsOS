# nxtsOS v0.2.0 — Release Manifest

- Version: 0.2.0 (Phase 3)
- Project location: `~/workspace/nxtsOS`
- Kernel binary: `build/nxtsOS.bin`
- Bootable image: `build/nxtsOS.iso` (El Torito via grub-mkrescue)
- Build command: `./scripts/build.sh` (log: `logs/build.log`)
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Git tag: `v0.2.0` (local repository only)
- Source archive: `archives/code/nxtsOS-v0.2.0-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.2.0-dist.zip`
- Checksums: `releases/v0.2.0/SHA256SUMS` (also inside the dist zip)

## Implemented (v0.2.0)

Everything in v0.1.1, plus: paging (32 MB identity-mapped kernel region,
per-process page directories), GDT user segments + TSS, ring-3 user
processes, int 0x80 syscalls (print, yield, exit, getpid, ticks) with
pointer validation, round-robin scheduler with yield and 100 ms timer
preemption, and a kernel shell that still works after the processes exit.

## NOT implemented (explicit)

Graphical desktop/window manager, GUI applications, filesystem/persistent
storage, networking, mouse, disk drivers, UEFI, process teardown (exited
processes' frames are not freed yet). See `docs/ROADMAP.md`.

## Remote publishing

NOT DONE. No authorised git-host account was connected, so nothing was
pushed. To publish later:

```sh
git remote add origin <your-new-private-repo-url>
git push -u origin main
git push origin v0.2.0
```

Prefer private initially; make public only with explicit authorisation.
