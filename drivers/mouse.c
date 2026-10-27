#include "mouse.h"
#include "../kernel/fb.h"

static int present = 0;
static s32 mx = 400, my = 300;
static int left = 0, middle = 0, right = 0;
static int left_edge = 0; /* set on press, cleared by mouse_left_pressed() */
static u8 packet[3];
static int pkt_idx = 0;

int mouse_present(void) { return present; }
s32 mouse_x(void) { return mx; }
s32 mouse_y(void) { return my; }
int mouse_left(void) { return left; }
int mouse_middle(void) { return middle; }
int mouse_right(void) { return right; }
int mouse_left_pressed(void) {
    int e = left_edge; left_edge = 0; return e;
}

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
/* Send a command byte to the mouse and read its ACK (0xFA). */
static int mouse_cmd(u8 cmd) {
    if (wait_in_empty() != 0) return -1;
    outb(0x64, 0xD4); /* write to mouse */
    if (wait_in_empty() != 0) return -1;
    outb(0x60, cmd);
    if (wait_out_full() != 0) return -1;
    return inb(0x60) == 0xFA ? 0 : -1;
}

int mouse_init(void) {
    /* Enable the auxiliary (mouse) port, then enable data reporting. */
    if (wait_in_empty() != 0) return 0;
    outb(0x64, 0xA8); /* enable aux port */
    if (mouse_cmd(0xF4) != 0) return 0; /* enable data reporting */
    /* Drain any pending packet bytes so the next IRQ starts a packet. */
    pkt_idx = 0;
    present = 1;
    return 1;
}

/* Test-only: set mouse state directly, bypassing PS/2 packets.
   Used by wm_autotest to script clicks/drags without relying on
   QEMU monitor mouse injection (which did not deliver packets in
   this sandbox, see docs/GRAPHICS.md). */
void mouse_test_set(s32 x, s32 y, int left_btn) {
    mx = x; my = y;
    if (left_btn && !left) left_edge = 1;
    left = left_btn;
}

void mouse_irq_handler(void) {
    mouse_feed_byte(inb(0x60));
}

/* Packet assembly, shared by IRQ handler and mousetest injection. */
void mouse_feed_byte(u8 b) {
    packet[pkt_idx++] = b;
    if (pkt_idx < 3) return;
    pkt_idx = 0;
    u8 b0 = packet[0];
    /* Bit 3 must be set in a valid first packet byte; if it is not,
       this packet is out of sync and is dropped. */
    if ((b0 & 0x08) == 0) return;
    int new_left = (b0 & 0x01) != 0;
    if (new_left && !left) left_edge = 1;
    left = new_left;
    middle = (b0 & 0x04) != 0;
    right = (b0 & 0x02) != 0;
    /* Overflow bits mean the delta is unreliable: ignore movement. */
    if ((b0 & 0xC0) == 0) {
        s32 dx = (s32)(char)packet[1];
        s32 dy = (s32)(char)packet[2];
        /* PS/2 Y is positive upwards; screen Y is positive downwards. */
        mx += dx; my -= dy;
    }
    s32 max_x = fb_ready() ? (s32)fb_width() - 1 : 799;
    s32 max_y = fb_ready() ? (s32)fb_height() - 1 : 599;
    if (mx < 0) mx = 0;
    if (my < 0) my = 0;
    if (mx > max_x) mx = max_x;
    if (my > max_y) my = max_y;
}
