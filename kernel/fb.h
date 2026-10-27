#ifndef NXTS_FB_H
#define NXTS_FB_H
#include "common.h"
/* Linear framebuffer (VBE via Multiboot, 32bpp only).
   fb_init must be called after vmm_init (it maps the framebuffer
   into kernel space) and before any drawing. If GRUB did not set a
   graphics mode, fb_init returns -1 and all drawing functions are
   no-ops — the system then runs text-only, it does not panic.
   All coordinates in drawing functions are s32 and are clipped to
   the screen; negative or off-screen coordinates never index the
   framebuffer out of bounds. */
int  fb_parse(u32 mbi_addr); /* early, before PMM: save framebuffer info from Multiboot */
int  fb_init(void); /* after vmm_init: map the saved framebuffer */
int  fb_ready(void);
u32  fb_width(void);
u32  fb_height(void);
u32  fb_pitch(void);
u32  fb_phys_addr(void);
void fb_clear(u32 colour);
void fb_putpixel(s32 x, s32 y, u32 colour);
void fb_fill_rect(s32 x, s32 y, s32 w, s32 h, u32 colour);
/* Fill with clipping to an additional clip rectangle (for windows). */
void fb_fill_rect_clip(s32 x, s32 y, s32 w, s32 h, u32 colour,
                       s32 cx, s32 cy, s32 cw, s32 ch);
void fb_draw_char(s32 x, s32 y, char ch, u32 fg, u32 bg);
void fb_draw_text(s32 x, s32 y, const char *s, u32 fg, u32 bg);
void fb_draw_text_clip(s32 x, s32 y, const char *s, u32 fg, u32 bg,
                       s32 cx, s32 cy, s32 cw, s32 ch);
u32  fb_read_pixel(s32 x, s32 y); /* 0 if out of bounds */
u32  fb_checksum(void); /* simple sum of all pixels, for tests */
#define FB_VIRT 0x40000000u
#endif
