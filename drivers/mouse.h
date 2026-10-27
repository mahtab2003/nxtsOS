#ifndef NXTS_MOUSE_H
#define NXTS_MOUSE_H
#include "../kernel/common.h"
/* PS/2 mouse, IRQ12, 3-byte packets. Returns 1 if a mouse responded
   to initialisation, 0 otherwise (GUI still works, cursor just
   never moves). Position is clamped to the framebuffer size when a
   framebuffer is present, else to 800x600. Packets with an X or Y
   overflow bit set are ignored for movement (their deltas are
   unreliable) but their button state is still applied. */
int  mouse_init(void);
void mouse_irq_handler(void);
int  mouse_present(void);
s32  mouse_x(void);
s32  mouse_y(void);
int  mouse_left(void);
int  mouse_middle(void);
int  mouse_right(void);
int  mouse_left_pressed(void); /* edge: became pressed since last call */
void mouse_feed_byte(u8 b); /* packet assembly, for mousetest injection */
void mouse_test_set(s32 x, s32 y, int left_btn); /* test-only: set state directly */
void mouse_set_scale(int s); /* 0=half, 1=normal, 2=double (Phase 8 settings) */
int  mouse_scale(void);
#endif
