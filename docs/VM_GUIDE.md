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

## Bochs on Android (v0.7.3, user-tested config, kernel fix)

- The user's Android Bochs config that works for graphics:
  Storage ata0-master disk `nxtsOS-disk.img`, ata0-slave CDROM
  `nxtsOS.iso`, Boot cdrom; Hardware i440fx, 32 MB RAM,
  VGA Card "Bochs VBE (PCI)", PCI Slot1 "pcivga". With that
  config v0.7.2 already booted with "Framebuffer: 800x600,
  pitch 3200, phys 0xC0000000 (Multiboot)" — graphics was NOT
  the problem in the Android video, keyboard input was.
- v0.7.3 fixes the kernel side (PS/2 controller init + drain,
  see docs/GRAPHICS.md and releases/v0.7.3/MANIFEST.md). After
  boot, the first shell prompt prints "Keyboard: startup
  drained N byte(s)". Report that line with any new keyboard
  failure: N > 0 means a lodged byte was drained by this build;
  N = 0 and keys still dead means no bytes are reaching the
  controller at all — the Android app is dropping its system
  soft-keyboard input before Bochs, and no kernel change can
  fix that. In that case try, in order: (1) the Bochs app's
  own built-in virtual PC keyboard (app menu, if your app
  provides one — it sends real PS/2 scancodes, unlike a system
  IME which sends text), (2) a physical USB/Bluetooth keyboard
  attached to the phone, (3) QEMU on a PC, where keyboard
  input is tested and working.
- Once you can type, run `gui` to start the window manager,
  or `kbdstat` to see controller status and last scancode.

## Desktop shell (v0.8.0)

- At the shell prompt, run `desktop` (not `gui`) for the
  desktop shell: icons down the left, Start launcher, taskbar
  with clock, notifications and quick settings, and a lock
  screen. `gui` is still the older Phase 7 demo.
- Calculator: build a disk that contains `calc.nxpkg` (it is
  in the distribution zip), boot, log in as root, run
  `pkg install calc.nxpkg`, then run `desktop` and click the
  Calc icon (or Start → Calculator). Do NOT put a plain
  `calc.elf` on the same disk, or the install is refused
  ("file already exists on disk").
- Settings: open Settings from an icon or the launcher, change
  a value, click Save. Settings persist in `settings.txt` on
  the disk. If you log in as a non-root user and settings.txt
  is root-owned, Save is refused — that is the intended
  permission check, not a bug.
- Lock: click Start → Lock, or the Lock icon. In setup mode
  (no users file) press Enter to unlock. With users, type the
  session user's password. Three wrong passwords halt the
  system, same as text login lockout.

## GUI lag (v0.7.4, further improved in v0.8.0)

- If the GUI feels laggy, the main cause in v0.7.0-0.7.3 was
  kernel redraw volume (full screen on every mouse move,
  cursor only updated every 0.5s with the button up) — fixed
  in v0.7.4 by cursor save/restore, dirty-rect redraw, and
  30 Hz throttling. Test v0.7.4 before changing emulator
  settings.
- Bochs display refresh also caps smoothness: the shipped
  desktop bochsrc now uses update_freq=30 (was 5). On Android
  Bochs, if your app exposes a display update frequency,
  set it to 20-30; if it does not, the kernel fixes still
  apply, but the display will refresh at the app's rate.
- Bochs on a phone will always be slower than QEMU on a PC
  (interpreter vs dynamic translation). For the smoothest
  GUI, test on QEMU on a PC.
- v0.8.0 adds true per-window clipping (only the dirty rect
  of each window is redrawn, and the taskbar is skipped when
  the dirty rect does not reach it) and raises the pending
  redraw throttle from 30 Hz to 50 Hz. `cliptest` proves a
  clipped redraw produces exactly the same pixels as a full
  redraw. Residual lag you still feel in QEMU is mostly
  host-side: QEMU's PS/2 mouse is relative, so the host
  pointer and the guest cursor are both visible unless you
  grab the mouse in QEMU (Ctrl+Alt+G), and QEMU's display
  refresh means the guest cursor trails the host pointer by
  roughly 30–50 ms regardless — the kernel cannot fix
  host-side latency, and a USB tablet (absolute mouse) is
  impossible without a USB driver, which nxtsOS does not
  have yet.
