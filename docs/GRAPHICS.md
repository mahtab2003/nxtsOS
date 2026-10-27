# nxtsOS graphics and input (v0.7.0)

## What it is

Phase 7: a real graphics mode, a font, a mouse driver, and a window
manager — all in the kernel, all verified in QEMU. This is the
foundation for the Phase 8 desktop shell, not the desktop itself:
there is no graphical login, no settings app, and no user GUI
programs yet (those are Phase 8, as packages).

## Graphics mode

The kernel asks GRUB (via the Multiboot header) for a linear
framebuffer, 800x600x32. GRUB sets the mode and passes the
framebuffer address, pitch, and size in the Multiboot info
structure. Two real bugs were found and fixed while getting this
to work, and are worth recording so they are not reintroduced:

1. **GRUB reads the video fields at a fixed offset (32).** The
   first version put the video fields immediately after the
   checksum (offset 12), and GRUB read boot code as the mode type
   ("unsupported graphical mode type 2045232924") and refused to
   boot. The header now includes five zero address fields so the
   video fields land at offset 32.
2. **The framebuffer fields are not at offset 92.** The VBE fields
   in the Multiboot info are 2 bytes each, so the framebuffer
   section starts at offset 88, not 92: address (u64) at 88, pitch
   at 96, width at 100, height at 104, bpp at 108, type at 109.
   The first version read them 4 bytes too late and saw pitch 800,
   600x288, bpp 16 — and correctly rejected the mode.
3. **The Multiboot info page is overwritten by PMM.** GRUB's info
   structure lives in a page the memory map reports as free, so
   reading it after PMM/vmm allocation saw a cleared flags word.
   `fb_parse()` now saves the framebuffer info at the very start
   of `kmain`, before PMM, and `fb_init()` maps it after paging.
4. **The framebuffer must be shared with user page directories.**
   A user program's print syscall goes through the console, which
   in graphics mode writes to the framebuffer at 0x40000000. If
   that virtual address is unmapped in a user PD, the first user
   print page-faults. `vmm_create_pd()` now copies the kernel PD's
   framebuffer entry (256, supervisor pages) into every user PD,
   and `vmm_destroy_pd()` never frees it. User code (ring 3) still
   cannot access those supervisor pages directly — only kernel
   code in syscall context (ring 0) can.

If GRUB cannot set the mode, the kernel boots in VGA text mode
and the GUI commands report "no framebuffer available" instead of
panicking.

## Text console in graphics mode

The console keeps a RAM text buffer (80x25) and renders it to
either VGA text memory or, after `fb_init()`, to the framebuffer
with an 8x16 bitmap font. Early boot logs are buffered in RAM and
appear on screen in graphics mode too, after the framebuffer is
mapped. The font is generated at build time from the host's
standard console font (`tools/genfont.py`, default
Lat15-VGA16.psf.gz, 256 glyphs, MSB = leftmost pixel); the
generated `kernel/font_data.h` is committed so builds do not need
the host font. The font data itself is a standard console font,
not nxtsOS original code.

## Mouse

PS/2 mouse, IRQ12, 3-byte packets, enabled via the keyboard
controller (aux port enable, then 0xF4 enable data reporting).
The driver clamps the position to the framebuffer size, ignores
movement from packets with an X/Y overflow bit set (their deltas
are unreliable) but still applies their button state, and drops
packets whose first byte does not have bit 3 set (out of sync).
PIC masks were changed to unmask the slave cascade (master IRQ2)
and IRQ12, which text-mode-only kernels did not need.

## Window manager

In-kernel demo windows, drawn directly to the framebuffer with
clipping — no per-window pixel buffers, so a huge window cannot
exhaust memory; it is clamped to the screen instead. Features:
move (drag title bar), resize (drag bottom-right corner),
minimise (to the taskbar), maximise/restore, close, focus and
z-order (click brings a window to front), taskbar with a "Shell"
button and one button per window, and widgets that work: button,
label, and text field (click to focus, type, backspace, Enter
logs the text to serial).

Shell commands: `gui` (interactive window manager, exits via the
taskbar Shell button or a window's "Back to shell" button, then
the text console is redrawn), `guitest` (non-interactive edge
cases), `wmautotest` (scripted click/drag/taskbar test),
`mousetest` (PS/2 packet parsing, clamping, overflow), `mouse`
(print current mouse state), `mousepoll` (diagnostic: poll the
controller for bytes, used while diagnosing QEMU mouse injection).

## What is NOT tested, stated plainly

**Real mouse movement via QEMU/VNC did not work in this sandbox.**
QEMU monitor `mouse_move`/`mouse_button`, `mouse_set`, and VNC
PointerEvent messages were all tried (with `-display none`, VNC,
and `-vga std`), and none delivered a single PS/2 packet to the
guest — proven by polling the controller (`mousepoll` saw no
bytes) and by a serial debug log in the IRQ handler (no packets).
The mouse driver itself is proven: `mousetest` feeds known packets
directly to the driver's packet assembly and checks position,
clamping, overflow, and buttons, all PASS. The window manager's
click/drag/taskbar logic is proven: `wmautotest` scripts mouse
states directly into the WM loop (OK click, title-bar drag to
140,90, Shell exit), all PASS. What is NOT proven in QEMU is the
last hop — a real pointer device (or a desktop QEMU/VNC client)
moving the guest cursor — because the sandbox's QEMU would not
inject those packets at all. Test `gui` with a real mouse on your
machine (QEMU with a display, or VirtualBox) and report what
happens; that is the one Phase 7 interaction that still needs a
real-device check.

Also not in Phase 7: graphical login/desktop shell (Phase 8),
user GUI programs via syscalls (Phase 8, as packages), mouse
wheel/scroll, and a second mouse button menu. A button press,
dragged off the button, and released elsewhere does NOT trigger
the button (fixed during autotest development — the first version
triggered on release regardless of position).
