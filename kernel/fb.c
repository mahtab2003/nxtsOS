#include "fb.h"
#include "font_data.h"
#include "../mm/vmm.h"

static int ready = 0;
static u32 width = 0, height = 0, pitch = 0, phys = 0;
static u32 *fb = 0; /* virtual address FB_VIRT, 32bpp pixels */
/* Diagnostics for `fbinfo`: what GRUB actually passed, so a "no
   framebuffer" report can be diagnosed instead of guessed at. */
static const char *diag_reason = "not parsed";
static const char *parse_reason = "not parsed";
static int diag_bpp = -1, diag_type = -1;
const char *fb_diag_reason(void) { return diag_reason; }
const char *fb_parse_reason(void) { return parse_reason; }
int fb_diag_bpp(void) { return diag_bpp; }
int fb_diag_type(void) { return diag_type; }

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
    if ((mbi[0] & (1u << 12)) == 0) { diag_reason = "GRUB passed no framebuffer info (flag 12 clear)"; parse_reason = diag_reason; return -1; }
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
    diag_bpp = (int)bpp; diag_type = (int)type;
    if (fb_hi != 0 || fb_lo == 0 || (fb_lo & 0xFFF) != 0) { diag_reason = "framebuffer address invalid (high word set, zero, or unaligned)"; parse_reason = diag_reason; return -1; }
    if (bpp != 32 || type != 1) { diag_reason = "unsupported mode (only 32bpp RGB, type 1, is supported)"; parse_reason = diag_reason; return -1; }
    if (w == 0 || h == 0 || w > 4096 || h > 4096 || p < w * 4) { diag_reason = "invalid dimensions or pitch"; parse_reason = diag_reason; return -1; }
    phys = fb_lo; pitch = p; width = w; height = h;
    parsed = 1; diag_reason = "ok"; parse_reason = "ok";
    return 0;
}

/* Bochs VBE fallback (v0.7.1): if GRUB did not set a graphics mode
   — the reported failure in Bochs, where the kernel booted in text
   mode and `gui`/`guitest` said "no framebuffer available" — try to
   set one directly. Bochs VBE (also QEMU's std VGA, which is
   Bochs-compatible) is driven via IO ports 0x1CE (index) and 0x1CF
   (data): ID 0, XRES 1, YRES 2, BPP 3, ENABLE 4 (bit 0 = enabled,
   bit 6 = linear framebuffer), VIRT_WIDTH 6, VIRT_HEIGHT 7. The
   linear framebuffer address is NOT a VBE register: it is the PCI
   BAR0 of the display device, read via PCI config ports 0xCF8/
   0xCFC. We scan bus 0 for a class-0x03 (display) device instead
   of hardcoding a slot, and we never guess an address: if no PCI
   display BAR is found, the fallback fails cleanly and the system
   stays in text mode. */
static void vbe_write(u16 index, u16 val) { outw(0x1CE, index); outw(0x1CF, val); }
static u16 vbe_read(u16 index) { outw(0x1CE, index); return inw(0x1CF); }
static u32 pci_read32(u32 dev, u32 func, u32 off) {
    outl(0xCF8, 0x80000000u | (dev << 11) | (func << 8) | (off & 0xFC));
    return inl(0xCFC);
}
int fb_vbe_try(void) {
    vbe_write(0, 0xB0C2);
    u16 id = vbe_read(0);
    if (id < 0xB0C0 || id > 0xB0CF) { diag_reason = "VBE fallback: no Bochs VBE device (ID check failed)"; return -1; }
    u32 bar = 0;
    for (u32 dev = 0; dev < 32; dev++) {
        u32 vendor = pci_read32(dev, 0, 0) & 0xFFFF;
        if (vendor == 0xFFFF) continue;
        u32 class_code = pci_read32(dev, 0, 0x08) >> 24;
        if (class_code != 0x03) continue;
        u32 b0 = pci_read32(dev, 0, 0x10);
        if (b0 & 1) continue; /* IO BAR, not a framebuffer */
        bar = b0 & 0xFFFFFFF0u;
        if (bar != 0) break;
    }
    if (bar == 0) {
        /* Bochs with an ISA (non-PCI) VGA card, which is the default
           when no PCI VGA slot is configured: OSDev documents the
           linear framebuffer at the fixed address 0xE0000000 in
           that case ("modern versions will use that address when
           emulating ISA-only systems"). This is only reached after
           the Bochs VBE ID check passed, so a Bochs VBE device is
           definitely present, and the address is verified by a
           write/read test pixel after mapping (see fb_verify in
           main.c) — a wrong address fails verification and falls
           back to text mode, it does not corrupt memory. */
        bar = 0xE0000000u;
    }
    vbe_write(1, 800); vbe_write(2, 600); vbe_write(3, 32);
    vbe_write(6, 800); vbe_write(7, 600);
    vbe_write(4, 0x41); /* enabled + linear framebuffer, clear memory */
    if (vbe_read(1) != 800 || vbe_read(2) != 600 || vbe_read(3) != 32) {
        vbe_write(4, 0); diag_reason = "VBE fallback: mode 800x600x32 was not accepted"; return -1;
    }
    phys = bar; pitch = 800 * 4; width = 800; height = 600;
    parsed = 1; diag_reason = "ok (VBE fallback)";
    return 0;
}

void fb_disable(void) { ready = 0; fb = 0; }
void fb_vbe_disable(void) { vbe_write(4, 0); }
int fb_verify(void) {
    if (!ready) return -1;
    u32 saved = fb[0];
    fb[0] = 0x00AABBCCu;
    u32 back = fb[0];
    fb[0] = saved;
    return back == 0x00AABBCCu ? 0 : -1;
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
    /* v0.7.4: row-pointer fill. The old version indexed
       fb[yy * (pitch/4) + xx] for every pixel, which is a multiply
       per pixel in the emulated CPU; a row pointer turns the inner
       loop into a plain sequential store, which the compiler can
       turn into wide stores. This is the single biggest per-pixel
       win for full-screen fills (background = 480,000 pixels). */
    u32 row_stride = pitch / 4;
    for (s32 yy = y0; yy < y1; yy++) {
        u32 *row = fb + (u32)yy * row_stride + (u32)x0;
        for (s32 xx = x0; xx < x1; xx++) *row++ = colour;
    }
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
    u32 row_stride = pitch / 4;
    for (int row = 0; row < 16; row++) {
        s32 yy = y + row;
        if (yy < 0 || yy >= (s32)height) continue;
        u8 bits = glyph[row];
        u32 *rowp = fb + (u32)yy * row_stride;
        for (int col = 0; col < 8; col++) {
            s32 xx = x + col;
            if (xx < 0 || xx >= (s32)width) continue;
            rowp[xx] = (bits & (0x80 >> col)) ? fg : bg;
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
    u32 row_stride = pitch / 4;
    for (const char *p = s; *p; p++) {
        /* Clip the glyph's x range once, then draw the row
           without a per-pixel bounds check (v0.7.4: the old
           version checked xx/cx0/cx1 for every one of the
           128 pixels of every glyph, on every full redraw). */
        s32 gx0 = cur_x, gx1 = cur_x + 8;
        if (gx0 < cx0) gx0 = cx0;
        if (gx1 > cx1) gx1 = cx1;
        const u8 *glyph = font8x16[(u8)*p];
        for (int row = 0; row < 16; row++) {
            s32 yy = y + row;
            if (yy < cy0 || yy >= cy1) continue;
            u8 bits = glyph[row];
            u32 *rowp = fb + (u32)yy * row_stride;
            for (s32 xx = gx0; xx < gx1; xx++) {
                int col = (int)(xx - cur_x);
                rowp[xx] = (bits & (0x80 >> col)) ? fg : bg;
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
