#include "keyboard.h"
#include "mouse.h"

/* PS/2 set 1, US layout. Index = scancode. 0 = no printable key. */
static const char normal[128] = {
    0, 0, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', 0,
    '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', 0,
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`',
    0, '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0,
    '*', 0, ' ',
};
static const char shifted[128] = {
    0, 0, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', 0,
    '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', 0,
    0, 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~',
    0, '|', 'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?', 0,
    '*', 0, ' ',
};

#define BUF_SIZE 256
static volatile char buf[BUF_SIZE];
static volatile u32 head = 0, tail = 0;
static volatile int shift = 0, extended = 0;
/* v0.7.3 diagnostics: bytes drained from the controller at startup
   (lodged GRUB/BIOS bytes that would otherwise block all input),
   and the last raw scancode received. */
static u32 init_drained = 0;
static u32 post_drained = 0;
static volatile u8 last_sc = 0;

static int wait_in_empty(void) {
    for (u32 i = 0; i < 100000; i++)
        if ((inb(0x64) & 0x02) == 0) return 0;
    return -1;
}
static int wait_out_full(void) {
    for (u32 i = 0; i < 100000; i++)
        if (inb(0x64) & 0x01) return 0;
    return -1;
}
/* Drain the controller's 1-byte output buffer, discarding whatever
   is in it. Bounded: with both ports disabled no new bytes should
   arrive, so this normally drains 0 or 1 bytes and returns. */
static u32 drain_output(void) {
    u32 n = 0;
    while (n < 32 && (inb(0x64) & 0x01)) { (void)inb(0x60); n++; }
    return n;
}

/* Proper PS/2 controller initialisation, v0.7.3. Before v0.7.3
   keyboard_init() only reset the software buffer: the controller
   itself was never touched, so a byte left in its 1-byte output
   buffer by GRUB/BIOS (a key pressed or released while GRUB was
   loading the kernel, a held key repeating, a BIOS BAT byte) stayed
   there forever. The PIC is reinitialised after that byte's IRQ
   was latched, so the IRQ is forgotten, and because the output
   buffer is full the controller accepts no new keyboard bytes and
   raises no new IRQ: the keyboard looks dead from the first prompt
   on, on any emulator, until the buffer is read. Pressing keys
   repeatedly during boot sometimes cleared it (a byte read by a
   later IRQ/poll), which is exactly the "works only if I mash
   Enter during loading" symptom. The fix: disable both ports,
   flush the output buffer, set the configuration byte (IRQ1 +
   IRQ12 + translation on, keyboard clock enabled), re-enable the
   keyboard port, flush again, and explicitly set scancode set 2
   (the BIOS standard; with translation on the CPU sees set 1,
   which this driver expects). Every step has a timeout and a
   fallback: if any step times out, init aborts that step and the
   boot continues with whatever the BIOS left behind, so a
   controller that does not answer a command can never make
   booting worse than v0.7.2 was. */
void keyboard_init(void) {
    head = 0; tail = 0; shift = 0; extended = 0;
    init_drained = 0; last_sc = 0;
    if (wait_in_empty() == 0) outb(0x64, 0xAD); /* disable kbd port */
    if (wait_in_empty() == 0) outb(0x64, 0xA7); /* disable aux port */
    init_drained += drain_output();
    /* Read, patch, and write back the configuration byte. */
    if (wait_in_empty() == 0) {
        outb(0x64, 0x20); /* read config byte */
        if (wait_out_full() == 0) {
            u8 cfg = inb(0x60);
            /* Some controllers (Bochs) send a second byte (0xD8)
               after a config read; it is not a key, drain it. */
            init_drained += drain_output();
            u8 newcfg = (u8)((cfg | 0x43) & ~0x10);
            if (wait_in_empty() == 0) {
                outb(0x64, 0x60); /* write config byte */
                if (wait_in_empty() == 0) outb(0x60, newcfg);
            }
        }
    }
    if (wait_in_empty() == 0) outb(0x64, 0xAE); /* enable kbd port */
    init_drained += drain_output();
    /* Set scancode set 2. Keyboard commands go to port 0x60
       directly (0xD4 is mouse-only). ACK 0xFA expected twice. */
    if (wait_in_empty() == 0) {
        outb(0x60, 0xF0);
        if (wait_out_full() == 0 && inb(0x60) == 0xFA) {
            if (wait_in_empty() == 0) {
                outb(0x60, 0x02);
                if (wait_out_full() == 0) {
                    if (inb(0x60) != 0xFA) init_drained += drain_output();
                }
            }
        } else {
            init_drained += drain_output(); /* resend byte 0xFE, if any */
        }
    }
}

u32 keyboard_init_drained(void) { return init_drained; }
u32 keyboard_startup_drained(void) { return init_drained + post_drained; }
u8 keyboard_last_scancode(void) { return last_sc; }
u8 keyboard_controller_status(void) { return inb(0x64); }
/* Drain the controller output buffer now (used after mouse_init,
   which can leave a mouse byte behind). Returns bytes drained. */
u32 keyboard_drain_controller(void) {
    u32 n = drain_output();
    post_drained += n;
    return n;
}

static void push_char(char c) {
    u32 next = (head + 1) % BUF_SIZE;
    if (next != tail) { buf[head] = c; head = next; }
}

static void keyboard_feed(u8 sc) {
    last_sc = sc;
    if (sc == 0xE0) { extended = 1; return; }
    if (extended) { extended = 0; return; } /* arrows etc: ignored */
    if (sc == 0x2A || sc == 0x36) { shift = 1; return; }
    if (sc == 0xAA || sc == 0xB6) { shift = 0; return; }
    if (sc & 0x80) return; /* key release */
    if (sc == 0x0E) { push_char('\b'); return; }
    if (sc == 0x1C) { push_char('\n'); return; }
    if (sc < 128) {
        char c = shift ? shifted[sc] : normal[sc];
        if (c) push_char(c);
    }
}

void keyboard_irq_handler(void) { keyboard_feed(inb(0x60)); }

/* Poll the controller for a pending byte, without waiting for an
   IRQ. v0.7.2 polling only handled keyboard bytes and returned
   immediately on mouse data (status bit 5): if a mouse byte ever
   lodged in the 1-byte output buffer with its IRQ12 lost (the
   same PIC-clearing mechanism as the keyboard case), polling
   skipped it forever and every keyboard byte behind it was
   blocked too. v0.7.3 feeds mouse bytes to the mouse driver
   instead of skipping them, so a lodged mouse byte is drained
   and cannot block the keyboard. The shell wakes every 10 ms on
   the timer IRQ, so a pending byte is picked up within one tick
   even if its IRQ was lost. Normal IRQ-driven input is
   unaffected: the IRQ handler usually consumes the byte before
   polling runs, leaving the output buffer empty (a no-op). */
void keyboard_poll(void) {
    u8 status = inb(0x64);
    if ((status & 1) == 0) return; /* output buffer empty */
    if (status & 0x20) { mouse_feed_byte(inb(0x60)); return; }
    keyboard_feed(inb(0x60));
}

int keyboard_getchar(void) {
    if (head == tail) return -1;
    char c = buf[tail];
    tail = (tail + 1) % BUF_SIZE;
    return (int)c;
}

/* Discard any buffered keys. Used on login, lock, and logout, so a
   key typed during a previous session (or during a lock prompt) is
   never consumed as the next session's username, password, or first
   command. */
void keyboard_flush(void) { tail = head; }
