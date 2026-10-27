# nxtsOS v0.1.1 — Release Manifest

- Version: 0.1.1 (bugfix release over v0.1.0; no new features)
- Project location: `~/workspace/nxtsOS`
- Kernel binary: `build/nxtsOS.bin`
- Bootable image: `build/nxtsOS.iso` (El Torito via grub-mkrescue)
- Build command: `./scripts/build.sh` (log: `logs/build.log`)
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Git tag: `v0.1.1` (local repository only — see below)
- Source archive: `archives/code/nxtsOS-v0.1.1-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.1.1-dist.zip`
- Checksums: `releases/v0.1.1/SHA256SUMS` (also inside the dist zip)

## What changed from v0.1.0

One fix, and it is the reason v0.1.0 rebooted in a loop in QEMU:

- The kernel now installs its own GDT (`drivers/gdt.c`, `drivers/gdt.S`:
  null, code 0x08, data 0x10) before setting up interrupts.
- Root cause: v0.1.0 assumed GRUB's GDT used code 0x08 / data 0x10, but
  GRUB actually uses code 0x10 / data 0x18. The first timer interrupt
  therefore faulted trying to load CS=0x08, the fault handler used the
  same bad selector, and the CPU triple-faulted and reset — over and
  over, which is the reboot loop users saw. QEMU's interrupt log proved
  it: `INT=0x20` (timer) followed by `#GP` with error code 0x0008, then
  double fault, then reset, repeating from "nxtsOS kernel starting".

## Implemented (v0.1.1)

Same as v0.1.0, plus the GDT fix: Multiboot boot, VGA text console,
COM1 serial mirror, Multiboot memory-map parsing, bitmap PMM, own GDT,
IDT, PIC remap, PIT 100 Hz, PS/2 keyboard (US, set 1), in-kernel shell
(`help`, `mem`, `ticks`, `clear`, `reboot`), panic path.

## NOT implemented (explicit)

Graphical desktop/window manager, GUI applications, filesystem/persistent
storage, networking, user processes, syscalls, privilege separation, mouse,
disk drivers, UEFI. See `docs/ROADMAP.md` for the phase of each.

## Remote publishing

NOT DONE. No GitHub or other authorised git-host account was connected in
this session, so nothing was pushed and no remote repository was created.
To publish later, from the project directory:

```sh
git remote add origin <your-new-private-repo-url>
git push -u origin main
git push origin v0.1.1
```

Prefer a private repository initially; make it public only with explicit
authorisation. No secrets are in this tree.
