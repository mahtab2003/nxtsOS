# VM Guide — nxtsOS v0.3.0

## Tested configuration (v0.3.0)

- Emulator: QEMU (qemu-system-x86_64), machine `pc` (i440FX), CPU default
- RAM to test: **128 MB** (64 MB as a secondary run)
- **QEMU test status (v0.3.0): PASS** — see `releases/v0.3.0/TEST_REPORT.md`.
  Booted at 128 MB and 64 MB; user processes run and interleave, the
  filesystem mounts, and a file written before a guest reboot is read
  back after it.
- Display: VGA text mode 80x25 (no graphics mode yet)
- Input: PS/2 keyboard (QEMU default)
- Storage: nxtsFS disk image (16 MiB, `build/nxtsOS-disk.img`), attached
  as IDE primary master. Without a disk, the kernel still boots and the
  shell works; `fs`/`ls`/`cat`/`write`/`rm` report "no filesystem".
- Network: none in v0.3.0 (not implemented)
- Serial: COM1 captured to `logs/serial.log` by the launch scripts

## Run it

```sh
python3 tools/mkdisk.py build/nxtsOS-disk.img --add hello.txt:/path/to/hello.txt
./scripts/run_qemu.sh        # 128 MB, windowed, serial -> logs/serial.log
./scripts/run_qemu.sh 256    # override RAM in MB
```

`run_qemu.sh` attaches `build/nxtsOS-disk.img` automatically when it
exists. Or manually:

```sh
qemu-system-x86_64 -cdrom build/nxtsOS.iso -boot d -m 128 \
  -drive file=build/nxtsOS-disk.img,format=raw,if=ide,index=0 \
  -serial file:logs/serial.log -display default
```

After boot, two built-in test programs run first and print `P1 iter` /
`P2 iter` lines — wait a few seconds and the `nxts> ` prompt appears
(the kernel now prints "The nxts> shell prompt will appear when they
finish" so this is not mistaken for a stuck test run; keys typed early
are buffered). Type `help` at the `nxts> ` prompt. Try `ls`,
`cat hello.txt`, `write note.txt hello`, `ls`, `reboot`, then
`cat note.txt` — the file survives the reboot. `reboot` restarts the
guest.
Stop the VM by closing the QEMU window (or Ctrl-Alt-Q).

## VirtualBox

Not tested for v0.3.0. The ISO is a standard El Torito bootable image and
should boot in VirtualBox as a CD image, but that claim is untested and
therefore not made as a supported configuration. QEMU is the supported path.

## Known issues (v0.3.0)

- No graphics mode, no mouse, no network, no user login yet.
- Files have owner/mode recorded, but enforcement for non-root users
  does not exist yet — there are no users yet (Phase 5). Until then,
  filesystem access is via the kernel shell only (trusted, UID 0);
  user processes have no filesystem syscalls in this release.
- Keyboard is US layout, PS/2 set 1 only; some keys (e.g. arrows) are ignored.
- The kernel never formats a disk on its own; a disk with no valid
  nxtsFS is reported, not wiped. Format only with `tools/mkdisk.py`.
- Reboot uses the keyboard-controller reset line; on some VM configs it
  may instead require closing the VM window.


## Bochs (v0.7.2, tested in Bochs 2.7)

Use the shipped `config/vm/bochsrc.txt` (also in the dist zip):
`bochs -q -f bochsrc.txt` (adjust the ISO and VGABIOS paths to
your install). It sets `vga: extension=vbe` with the SeaBIOS
stdvga VGABIOS, 32 MB RAM, CDROM boot. Do NOT use Bochs' default
isavga VGABIOS or the cirrus extension for nxtsOS graphics —
both were tested and cannot set 800x600x32 in Bochs 2.7 +
SeaBIOS (see docs/GRAPHICS.md). After the shell prompt appears,
click inside the Bochs window first, then type — Bochs SDL only
delivers keys to the focused window.
