# VM Guide — nxtsOS v0.1.0

## Tested configuration (v0.1.0)

- Emulator: QEMU (qemu-system-x86_64), machine `pc` (i440FX), CPU default
- RAM to test: **128 MB** (64 MB as a secondary run)
- **QEMU test status (v0.1.1): PASS** — see `releases/v0.1.1/TEST_REPORT.md`.
  Booted at 128 MB and 64 MB, monitor-typed `help`/`mem`/`ticks` all work.
  v0.1.0 FAILED this test (reboot loop); v0.1.1 fixes it with its own GDT.
- Display: VGA text mode 80x25 (no graphics mode yet)
- Input: PS/2 keyboard (QEMU default)
- Storage: none required for v0.1.0 (ISO boots from CD; no disk, no persistence)
- Network: none in v0.1.0 (not implemented)
- Serial: COM1 captured to `logs/serial.log` by the launch scripts

## Run it

```sh
./scripts/run_qemu.sh        # 128 MB, windowed, serial -> logs/serial.log
./scripts/run_qemu.sh 256    # override RAM in MB
```

Or manually:

```sh
qemu-system-x86_64 -cdrom build/nxtsOS.iso -boot d -m 128 \
  -serial file:logs/serial.log -display default
```

Type `help` at the `nxts> ` prompt. `reboot` restarts the guest.
Stop the VM by closing the QEMU window (or Ctrl-Alt-Q).

## VirtualBox

Not tested for v0.1.0. The ISO is a standard El Torito bootable image and
should boot in VirtualBox as a CD image, but that claim is untested and
therefore not made as a supported configuration. QEMU is the supported path.

## Known issues (v0.1.0)

- No graphics mode, no mouse, no disk, no network, no user processes.
- Keyboard is US layout, PS/2 set 1 only; some keys (e.g. arrows) are ignored.
- The shell runs in the kernel; there is no privilege separation yet.
- Reboot uses the keyboard-controller reset line; on some VM configs it
  may instead require closing the VM window.
