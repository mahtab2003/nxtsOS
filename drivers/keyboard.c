#include "keyboard.h"

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

void keyboard_init(void) { head = 0; tail = 0; shift = 0; extended = 0; }

static void push_char(char c) {
    u32 next = (head + 1) % BUF_SIZE;
    if (next != tail) { buf[head] = c; head = next; }
}

static void keyboard_feed(u8 sc) {
    if (sc == 0xE0) { extended = 1; return; }
    if (extended) { extended = 0; return; } /* arrows etc: ignored in v0.1.0 */
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

/* Poll the keyboard controller for a pending key, without waiting
   for IRQ1. v0.7.2: a user reported that in Bochs the shell only
   accepted keys if keys had been pressed during boot — i.e. keys
   typed after the prompt appeared were lost. In this sandbox
   Bochs keyboard IRQ delivery works (verified via xdotool), so
   the exact trigger in the user's Bochs setup could not be
   reproduced, but polling removes the single point of failure:
   the shell wakes every 10 ms on the timer IRQ, so even if IRQ1
   is lost, masked, or delayed in some Bochs configuration, a
   pending key is still picked up within one timer tick. The
   status bit 5 check is essential: bit 5 set means the byte is
   mouse data, which must be left for the mouse IRQ handler —
   reading it here would corrupt mouse packets. If the output
   buffer is empty, or the byte is mouse data, this is a no-op,
   so normal IRQ-driven input is unaffected (the IRQ handler
   already consumed the byte by the time polling runs). */
void keyboard_poll(void) {
    u8 status = inb(0x64);
    if ((status & 1) == 0) return; /* output buffer empty */
    if (status & 0x20) return; /* mouse data, not keyboard */
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
   command — stale keys were a real cause of "terminal doesn't work
   after session close" reports. */
void keyboard_flush(void) { tail = head; }
