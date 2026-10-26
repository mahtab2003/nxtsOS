# nxtsOS Architecture (v0.1.0)

## Decision: modular monolithic kernel, 32-bit x86, Multiboot

Evaluated against a microkernel:

- Microkernel: better isolation, but IPC + driver servers + message passing
  would triple the code needed before anything boots or prints.
- Modular monolithic kernel: one address space, direct function calls between
  subsystems, clear module boundaries (`drivers/`, `mm/`, `fs/`, `net/` …)
  so a subsystem can later be split out. Simplest path to a booting,
  testable system on a small team, and the lowest RAM overhead.

Chosen: **modular monolithic, 32-bit x86 (i386), Multiboot 1 via GRUB**.
64-bit, paging, and user mode are Phase 3 work, not v0.1.0 claims.

## Boot path

```
BIOS -> GRUB (grub-mkrescue ISO, El Torito) -> Multiboot header in boot/boot.S
  -> stack setup -> kmain(multiboot_info, magic) -> console -> PMM -> IDT/PIC
  -> PIT + keyboard -> shell loop (hlt until interrupt)
```

The Multiboot magic (`0x2BADB002`) is checked; a wrong magic panics with
a message instead of silently continuing.

## v0.1.0 components

| Component | File(s) | What it does |
|---|---|---|
| Boot entry | `boot/boot.S`, `boot/linker.ld` | Multiboot header, 16 KiB stack, calls `kmain` |
| Console | `kernel/console.c` | VGA text (0xB8000, 80x25), scrolling, colour |
| Serial log | `drivers/serial.c` | COM1 38400 8N1, mirrors console output for QEMU capture |
| PMM | `mm/pmm.c` | Bitmap over Multiboot memory map, 4 KiB frames, `pmm_alloc/pmm_free`, free/used counts |
| Interrupts | `drivers/idt.c`, `drivers/pic.c` | 256-entry IDT, PIC remap to 0x20/0x28, exception stubs print vector + error code |
| Timer | `drivers/pit.c` | PIT channel 0, 100 Hz, `timer_ticks` counter, IRQ0 |
| Keyboard | `drivers/keyboard.c` | PS/2 set-1 scancodes, US layout, shift, backspace, Enter; IRQ1 ring buffer |
| Shell | `kernel/shell.c` | `help`, `mem`, `ticks`, `clear`, `reboot` (triple-fault-free: keyboard-controller reset) |
| Panic | `kernel/panic.c` | Prints message + halts with interrupts off |

## Memory layout (linker script)

Kernel linked at 1 MiB (`0x100000`), `.multiboot` first so GRUB finds the
header in the first 8 KiB. Stack is a 16 KiB BSS region. No paging yet:
v0.1.0 runs with identity-mapped physical memory as set up by GRUB.

## What is deliberately absent in v0.1.0

Paging/virtual memory, scheduler, processes, syscalls, VFS, drivers beyond
VGA/serial/PIC/PIT/keyboard, graphics modes, networking. Each has a
placeholder directory with a STATUS.md so the absence is explicit, not hidden.
