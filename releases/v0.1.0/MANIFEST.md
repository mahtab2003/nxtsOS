# nxtsOS v0.1.0 — Release Manifest

- Version: 0.1.0
- Project location: `~/workspace/nxtsOS`
- Kernel binary: `build/nxtsOS.bin` (13,552 bytes at packaging)
- Bootable image: `build/nxtsOS.iso` (5,136,384 bytes, El Torito via grub-mkrescue)
- Build command: `./scripts/build.sh` (log: `logs/build.log`)
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Multiboot header: at load address 0x100000, magic 0x1BADB002, flags 0x3,
  checksum valid (verified by parsing the ELF LOAD segment)
- Git tag: `v0.1.0` (local repository only — see below)
- Source archive: `archives/code/nxtsOS-v0.1.0-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.1.0-dist.zip`
- Checksums: `releases/v0.1.0/SHA256SUMS` (also inside the dist zip)

## Implemented (v0.1.0)

Multiboot boot, VGA text console, COM1 serial mirror, Multiboot memory-map
parsing, bitmap PMM, IDT, PIC remap, PIT 100 Hz, PS/2 keyboard (US, set 1),
in-kernel shell (`help`, `mem`, `ticks`, `clear`, `reboot`), panic path.

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
git push origin v0.1.0
```

Prefer a private repository initially; make it public only with explicit
authorisation. Never push secrets — there are none in this tree
(verified: no credentials, keys, or tokens in source or logs).
