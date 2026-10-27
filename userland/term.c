/* nxtsOS Console (Phase 10 GUI application, installed as a
   package via Phase 6, run from the desktop launcher).
   A local echo console: it is NOT the text shell (the desktop
   Terminal icon returns to that shell). It keeps a scrollback
   of typed lines and answers four built-in commands itself
   (help, echo, clear, about); it cannot run programs or read
   files, and it says so in its help text rather than
   pretending otherwise. Same no-libc, no-division rules as
   calc.c: syscalls go straight through int 0x80. */
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
static int sys_print(const char *s) { return syscall1(1, (int)s); }
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

#define NLINES 15
#define LINELEN 60
static char lines[NLINES][LINELEN];
static int nlines = 0;
static char input[LINELEN];
static int input_len = 0;

static void push_line(const char *s) {
    if (nlines < NLINES) {
        int i = 0;
        while (s[i] && i < LINELEN - 1) { lines[nlines][i] = s[i]; i++; }
        lines[nlines][i] = 0;
        nlines++;
        return;
    }
    for (int k = 0; k < NLINES - 1; k++) {
        int i = 0;
        while (lines[k + 1][i]) { lines[k][i] = lines[k + 1][i]; i++; }
        lines[k][i] = 0;
    }
    int i = 0;
    while (s[i] && i < LINELEN - 1) { lines[NLINES - 1][i] = s[i]; i++; }
    lines[NLINES - 1][i] = 0;
}
static int starts_with(const char *s, const char *p) {
    int i = 0;
    while (p[i]) { if (s[i] != p[i]) return 0; i++; }
    return 1;
}
static void draw_all(void) {
    gui_rect(0, 0, 478, 298, 0x00D0D0D0u);
    for (int i = 0; i < nlines; i++)
        gui_text(4, 4 + i * 16, 0x00000000u, 0x00D0D0D0u, lines[i]);
    char prompt[LINELEN + 3];
    prompt[0] = '>'; prompt[1] = ' ';
    int i = 0;
    while (i < input_len && i < LINELEN - 1) { prompt[2 + i] = input[i]; i++; }
    prompt[2 + i] = 0;
    gui_text(4, 4 + NLINES * 16, 0x00000000u, 0x00D0D0D0u, prompt);
}
static int run_command(void) {
    /* Returns 1 to exit. */
    if (input_len == 0) return 0;
    if (starts_with(input, "help") && (input[4] == 0)) {
        push_line("Commands: help, echo <text>, clear, about, exit");
        push_line("This console is local only: it cannot run");
        push_line("programs. Use the Terminal icon for the shell.");
        return 0;
    }
    if (starts_with(input, "echo ")) { push_line(input + 5); return 0; }
    if (starts_with(input, "clear") && input[5] == 0) { nlines = 0; return 0; }
    if (starts_with(input, "about") && input[5] == 0) {
        push_line("nxtsOS Console v1.0 (Phase 10)");
        return 0;
    }
    if (starts_with(input, "exit") && input[4] == 0) return 1;
    push_line("Unknown command. Type help.");
    return 0;
}

int main(void) {
    if (gui_open("Console", 160, 120, 480, 320) != 0) return 0;
    sys_print("term: window opened\n");
    push_line("nxtsOS Console. Type help.");
    draw_all();
    for (;;) {
        int ev[5];
        if (gui_event(ev) != 0) { sys_yield(); continue; }
        if (ev[0] == EV_CLOSE) break;
        if (ev[0] == EV_EXPOSE) { draw_all(); continue; }
        if (ev[0] == EV_KEY) {
            int ch = ev[3];
            if (ch == '\n') {
                char echo[LINELEN + 3];
                echo[0] = '>'; echo[1] = ' ';
                int i = 0;
                while (i < input_len) { echo[2 + i] = input[i]; i++; }
                echo[2 + i] = 0;
                push_line(echo);
                input[input_len] = 0;
                int quit = run_command();
                input_len = 0; input[0] = 0;
                draw_all();
                if (quit) break;
            } else if (ch == '\b') {
                if (input_len > 0) { input_len--; input[input_len] = 0; }
                draw_all();
            } else if (ch >= 32 && ch < 127 && input_len < LINELEN - 1) {
                input[input_len++] = (char)ch; input[input_len] = 0;
                draw_all();
            }
            continue;
        }
    }
    gui_close();
    return 0;
}
