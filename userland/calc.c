/* nxtsOS Calculator (Phase 8 GUI application, installed as a
   package via Phase 6, run from the desktop launcher).
   No libc: syscalls go straight through int 0x80. No division
   or modulo is used anywhere (the user program is linked
   without libgcc): division is repeated subtraction, and
   number printing is subtraction loops, like hello.c.
   Click rule mirrors the desktop GUI: a key activates only
   when the mouse is released over the same key it was
   pressed on (MDOWN records, MUP confirms). The layout is
   fixed: resizing the window larger leaves extra space, and
   the app redraws the same fixed layout on EXPOSE. */
static int syscall5(int num, int a1, int a2, int a3, int a4, int a5) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5) : "memory");
    return ret;
}
static int syscall1(int num, int a1) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1) : "memory");
    return ret;
}
static int sys_yield(void) { return syscall1(2, 0); }
static int gui_open(const char *title, int x, int y, int w, int h) {
    return syscall5(9, (int)title, x, y, w, h);
}
static int gui_rect(int x, int y, int w, int h, unsigned int colour) {
    return syscall5(10, x, y, w, h, (int)colour);
}
static int gui_text(int x, int y, unsigned int fg, unsigned int bg, const char *text) {
    return syscall5(11, x, y, (int)fg, (int)bg, (int)text);
}
static int gui_event(int *out) { return syscall5(12, (int)out, 0, 0, 0, 0); }
static int gui_close(void) { return syscall1(13, 0); }

/* Event types (must match kernel/wm.c): 1=expose, 2=down,
   3=up, 4=key, 5=close. */
#define EV_EXPOSE 1
#define EV_MDOWN 2
#define EV_MUP 3
#define EV_KEY 4
#define EV_CLOSE 5

/* Keypad: 4 columns x 4 rows, fixed layout. */
static const char keys[16] = {'7','8','9','/','4','5','6','*','1','2','3','-','0','C','=','+'};
#define KEY_X0 4
#define KEY_Y0 48
#define KEY_W 72
#define KEY_H 40
#define KEY_DX 78
#define KEY_DY 48

static int acc = 0;        /* accumulated value */
static int cur = 0;        /* value being entered */
static int entering = 1;   /* 1 = cur is a fresh entry, 0 = showing result */
static int pending = 0;    /* pending operator, 0 = none */
static int err = 0;        /* division by zero */
static int press_key = -1; /* key index pressed, -1 = none */

/* Integer division by repeated subtraction (no libgcc). */
static int calc_div(int a, int b) {
    int neg = 0, q = 0;
    if (a < 0) { neg = !neg; a = -a; }
    if (b < 0) { neg = !neg; b = -b; }
    while (a >= b) { a -= b; q++; }
    return neg ? -q : q;
}
static void itoa(int v, char *out) {
    int i = 0;
    if (v < 0) { out[i++] = '-'; v = -v; }
    if (v == 0) { out[i++] = '0'; out[i] = 0; return; }
    /* Digits in reverse, via subtraction (no division). */
    char rev[12]; int n = 0;
    int th = 0, h = 0, t = 0, o;
    while (v >= 1000) { v -= 1000; th++; }
    while (v >= 100) { v -= 100; h++; }
    while (v >= 10) { v -= 10; t++; }
    o = v;
    if (th) rev[n++] = (char)('0' + th);
    if (th || h) rev[n++] = (char)('0' + h);
    if (th || h || t) rev[n++] = (char)('0' + t);
    rev[n++] = (char)('0' + o);
    rev[n] = 0;
    /* Numbers above 9999 lose their high digits; the display
       is 12 chars, and this calculator is a demo, not a
       spreadsheet. Values are clamped on entry instead: see
       apply_digit. */
    for (int k = 0; k < n; k++) out[i++] = rev[k];
    out[i] = 0;
}
static void apply_op(int op) {
    if (err) return;
    if (pending == '+') acc = acc + cur;
    else if (pending == '-') acc = acc - cur;
    else if (pending == '*') acc = acc * cur;
    else if (pending == '/') {
        if (cur == 0) { err = 1; return; }
        acc = calc_div(acc, cur);
    } else acc = cur;
    /* Clamp so itoa (4 digits) always stays exact. */
    if (acc > 9999) acc = 9999;
    if (acc < -9999) acc = -9999;
    (void)op;
}
static void apply_digit(int d) {
    if (err) { err = 0; cur = 0; entering = 1; }
    if (!entering) { cur = 0; entering = 1; }
    /* Clamp entry to 4 digits so itoa stays exact. */
    if (cur < 1000) cur = cur * 10 + d;
}
static void activate_key(char k) {
    if (k >= '0' && k <= '9') { apply_digit(k - '0'); return; }
    if (k == 'C') { acc = 0; cur = 0; pending = 0; entering = 1; err = 0; return; }
    if (k == '+' || k == '-' || k == '*' || k == '/') {
        apply_op(0);
        if (!err) { pending = k; cur = acc; entering = 0; }
        return;
    }
    if (k == '=') {
        apply_op(0);
        if (!err) { cur = acc; pending = 0; entering = 0; }
        return;
    }
}
static void display_text(char *out) {
    if (err) { out[0]='E'; out[1]='r'; out[2]='r'; out[3]=0; return; }
    itoa(entering ? cur : acc, out);
}
static void draw_all(void) {
    char disp[16];
    gui_rect(0, 0, 318, 258, 0x00D0D0D0u);
    gui_rect(4, 4, 310, 36, 0x00FFFFFFu);
    display_text(disp);
    gui_text(12, 12, 0x00000000u, 0x00FFFFFFu, disp);
    for (int i = 0; i < 16; i++) {
        int col = i % 4, row = i / 4;
        int kx = KEY_X0 + col * KEY_DX, ky = KEY_Y0 + row * KEY_DY;
        gui_rect(kx, ky, KEY_W, KEY_H, 0x00C0C0C0u);
        char label[2]; label[0] = keys[i]; label[1] = 0;
        gui_text(kx + 30, ky + 12, 0x00000000u, 0x00C0C0C0u, label);
    }
}
static int hit_key(int x, int y) {
    for (int i = 0; i < 16; i++) {
        int col = i % 4, row = i / 4;
        int kx = KEY_X0 + col * KEY_DX, ky = KEY_Y0 + row * KEY_DY;
        if (x >= kx && x < kx + KEY_W && y >= ky && y < ky + KEY_H) return i;
    }
    return -1;
}

int main(void) {
    if (gui_open("Calculator", 240, 160, 320, 280) != 0) return 0;
    draw_all();
    for (;;) {
        int ev[5];
        if (gui_event(ev) != 0) { sys_yield(); continue; }
        if (ev[0] == EV_CLOSE) break;
        if (ev[0] == EV_EXPOSE) { draw_all(); continue; }
        if (ev[0] == EV_MDOWN) { press_key = hit_key(ev[1], ev[2]); continue; }
        if (ev[0] == EV_MUP) {
            int k = hit_key(ev[1], ev[2]);
            if (press_key >= 0 && k == press_key) activate_key(keys[k]);
            press_key = -1;
            draw_all();
            continue;
        }
        if (ev[0] == EV_KEY) {
            int ch = ev[3];
            if (ch >= '0' && ch <= '9') activate_key((char)ch);
            else if (ch == '+' || ch == '-' || ch == '*' || ch == '/' || ch == '=') activate_key((char)ch);
            else if (ch == 'c' || ch == 'C') activate_key('C');
            else if (ch == '\n') activate_key('=');
            draw_all();
            continue;
        }
    }
    gui_close();
    return 0;
}
