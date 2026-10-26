#include "fb.h"
#include "font_data.h"
#include "../mm/vmm.h"

static int ready = 0;
static u32 width = 0, height = 0, pitch = 0, phys = 0;
static u32 *fb = 0; /* virtual address FB_VIRT, 32bpp pixels */

int fb_ready(void) { return ready; }
u32 fb_width(void) { return width; }
u32 fb_height(void) { return height; }
u32 fb_pitch(void) { return pitch; }
u32 fb_phys_addr(void) { return phys; }

/* Parse and save the framebuffer info early, before PMM allocation:
   GRUB's Multiboot info structure lives in a page the memory map
   reports as free, so PMM/vmm allocations can overwrite it. Reading
   it after vmm_init (as the first version did) therefore saw a
   cleared flags word and reported "not available" even though GRUB
   had set an 800x600 graphics mode. */
static int parsed = 0;
int fb_parse(u32 mbi_addr) {
    u32 *mbi = (u32 *)mbi_addr;
    if ((mbi[0] & (1u << 12)) == 0) return -1; /* no framebuffer info */
    /* Multiboot info: framebuffer_addr is u64 at byte offset 88
       (VBE fields are 2 bytes each, so the framebuffer section
       starts 4 bytes earlier than a naive 4-byte-per-field count
       gives), pitch at 96, width at 100, height at 104, bpp at
       108, type at 109. Verified against GRUB's actual info in
       testing: pitch 3200, 800x600, bpp 32, type 1. */
    u8 *b = (u8 *)mbi_addr;
    u32 fb_lo = (u32)b[88] | ((u32)b[89] << 8) | ((u32)b[90] << 16) | ((u32)b[91] << 24);
    u32 fb_hi = (u32)b[92] | ((u32)b[93] << 8) | ((u32)b[94] << 16) | ((u32)b[95] << 24);
    u32 p = (u32)b[96] | ((u32)b[97] << 8) | ((u32)b[98] << 16) | ((u32)b[99] << 24);
    u32 w = (u32)b[100] | ((u32)b[101] << 8) | ((u32)b[102] << 16) | ((u32)b[103] << 24);
    u32 h = (u32)b[104] | ((u32)b[105] << 8) | ((u32)b[106] << 16) | ((u32)b[107] << 24);
    u8 bpp = b[108], type = b[109];
    if (fb_hi != 0 || fb_lo == 0 || (fb_lo & 0xFFF) != 0) return -1;
    if (bpp != 32 || type != 1) return -1; /* only 32bpp RGB is supported */
    if (w == 0 || h == 0 || w > 4096 || h > 4096 || p < w * 4) return -1;
    phys = fb_lo; pitch = p; width = w; height = h;
    parsed = 1;
    return 0;
}

int fb_init(void) {
    if (!parsed) return -1;
    /* Map the framebuffer into kernel space at FB_VIRT. */
    u32 bytes = pitch * height;
    for (u32 off = 0; off < bytes; off += 4096)
        vmm_map_page(vmm_kernel_pd(), FB_VIRT + off, phys + off, PAGE_RW);
    /* Flush the TLB so the new mappings are visible. */
    vmm_enable_paging(vmm_kernel_pd());
    fb = (u32 *)FB_VIRT;
    ready = 1;
    return 0;
}

void fb_clear(u32 colour) {
    if (!ready) return;
    for (u32 i = 0; i < width * height; i++) fb[i] = colour;
}

void fb_putpixel(s32 x, s32 y, u32 colour) {
    if (!ready) return;
    if (x < 0 || y < 0 || x >= (s32)width || y >= (s32)height) return;
    fb[(u32)y * (pitch / 4) + (u32)x] = colour;
}

static void fill_clip(s32 x, s32 y, s32 w, s32 h, u32 colour,
                      s32 cx, s32 cy, s32 cw, s32 ch) {
    if (!ready || w <= 0 || h <= 0) return;
    s32 x0 = x, y0 = y, x1 = x + w, y1 = y + h;
    if (x0 < cx) x0 = cx;
    if (y0 < cy) y0 = cy;
    if (x1 > cx + cw) x1 = cx + cw;
    if (y1 > cy + ch) y1 = cy + ch;
    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > (s32)width) x1 = (s32)width;
    if (y1 > (s32)height) y1 = (s32)height;
    if (x0 >= x1 || y0 >= y1) return;
    for (s32 yy = y0; yy < y1; yy++)
        for (s32 xx = x0; xx < x1; xx++)
            fb[(u32)yy * (pitch / 4) + (u32)xx] = colour;
}

void fb_fill_rect(s32 x, s32 y, s32 w, s32 h, u32 colour) {
    fill_clip(x, y, w, h, colour, 0, 0, (s32)width, (s32)height);
}
void fb_fill_rect_clip(s32 x, s32 y, s32 w, s32 h, u32 colour,
                       s32 cx, s32 cy, s32 cw, s32 ch) {
    fill_clip(x, y, w, h, colour, cx, cy, cw, ch);
}

void fb_draw_char(s32 x, s32 y, char ch, u32 fg, u32 bg) {
    if (!ready) return;
    const u8 *glyph = font8x16[(u8)ch];
    for (int row = 0; row < 16; row++) {
        u8 bits = glyph[row];
        for (int col = 0; col < 8; col++) {
            u32 colour = (bits & (0x80 >> col)) ? fg : bg;
            fb_putpixel(x + col, y + row, colour);
        }
    }
}

void fb_draw_text(s32 x, s32 y, const char *s, u32 fg, u32 bg) {
    fb_draw_text_clip(x, y, s, fg, bg, 0, 0, (s32)width, (s32)height);
}
void fb_draw_text_clip(s32 x, s32 y, const char *s, u32 fg, u32 bg,
                       s32 cx, s32 cy, s32 cw, s32 ch) {
    if (!ready) return;
    s32 cx0 = cx, cy0 = cy, cx1 = cx + cw, cy1 = cy + ch;
    if (cx0 < 0) cx0 = 0;
    if (cy0 < 0) cy0 = 0;
    if (cx1 > (s32)width) cx1 = (s32)width;
    if (cy1 > (s32)height) cy1 = (s32)height;
    s32 cur_x = x;
    for (const char *p = s; *p; p++) {
        /* Draw the glyph, but only pixels inside the clip rect. */
        const u8 *glyph = font8x16[(u8)*p];
        for (int row = 0; row < 16; row++) {
            s32 yy = y + row;
            if (yy < cy0 || yy >= cy1) continue;
            u8 bits = glyph[row];
            for (int col = 0; col < 8; col++) {
                s32 xx = cur_x + col;
                if (xx < cx0 || xx >= cx1) continue;
                fb[(u32)yy * (pitch / 4) + (u32)xx] = (bits & (0x80 >> col)) ? fg : bg;
            }
        }
        cur_x += 8;
        if (cur_x >= cx1) break;
    }
}

u32 fb_read_pixel(s32 x, s32 y) {
    if (!ready) return 0;
    if (x < 0 || y < 0 || x >= (s32)width || y >= (s32)height) return 0;
    return fb[(u32)y * (pitch / 4) + (u32)x];
}

u32 fb_checksum(void) {
    if (!ready) return 0;
    u32 sum = 0;
    for (u32 i = 0; i < width * height; i++) sum += fb[i] * 31u + 1u;
    return sum;
}
