# Hardware Support

## Supported in v0.1.0 (tested in QEMU)

- CPU: 32-bit x86 (i386+), QEMU `pc` machine
- Display: VGA text mode (0xB8000)
- Serial: COM1 (0x3F8) for diagnostics
- Interrupt controller: 8259 PIC
- Timer: 8254 PIT, 100 Hz
- Keyboard: PS/2, set 1 scancodes, US layout

## Not supported yet

- Mouse, ATA/SATA/NVMe disks, filesystems, Ethernet/Wi-Fi, sound, USB,
  ACPI power management, SMP, 64-bit long mode, UEFI (BIOS boot only via
  GRUB on the ISO).

Each future driver lands with its own QEMU test entry in the release
test report for the version that adds it.
