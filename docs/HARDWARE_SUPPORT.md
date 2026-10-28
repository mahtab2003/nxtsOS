# Hardware Support

## Supported in v0.1.0 (tested in QEMU) — still present

- CPU: 32-bit x86 (i386+), QEMU `pc` machine
- Display: VGA text mode (0xB8000) — still present as the fallback console
- Serial: COM1 (0x3F8) for diagnostics
- Interrupt controller: 8259 PIC
- Timer: 8254 PIT, 100 Hz
- Keyboard: PS/2, set 1 scancodes, US layout

## Added since v0.1.0

- Mouse: PS/2 mouse (v0.7.0, `drivers/mouse.c`) — drives the desktop cursor
- Display: linear framebuffer via VBE/Multiboot, 800x600x32 (v0.7.0,
  `kernel/fb.c`), with a Bochs VBE fallback (v0.7.2)
- Disk: ATA PIO sector read/write (v0.3.0, `drivers/ata.c`) under the
  nxtsfs filesystem (`fs/nxtsfs.c`)
- Network: Intel e1000 Ethernet, polled, no interrupts (v0.9.0,
  `net/e1000.c`)

CORRECTION: this file previously listed mouse, ATA disks, filesystems
and Ethernet under "Not supported yet" — that was the v0.1.0 position,
kept un-updated while those drivers shipped in v0.3.0, v0.7.0 and
v0.9.0. The list below is what remains unsupported.

## Not supported yet

- SATA/NVMe disks (ATA PIO only), Wi-Fi, sound, USB,
  ACPI power management, SMP, 64-bit long mode, UEFI (BIOS boot only via
  GRUB on the ISO).

Each future driver lands with its own QEMU test entry in the release
test report for the version that adds it.
