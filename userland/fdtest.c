/* Deep-core D2 test program: fd open/write/read/lseek/close on
   a regular file, anonymous pipe() self-test, and brk heap
   growth. Prints one line per check; exits 0 only if all pass.
   No libc: syscalls go straight through int 0x80. */
static int syscall3(int num, int a1, int a2, int a3) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1), "c"(a2), "d"(a3) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall3(1, (int)s, 0, 0); }
static int sys_ticks(void) { return syscall3(5, 0, 0, 0); }
static int sys_open(const char *n, int f) { return syscall3(14, (int)n, f, 0); }
static int sys_read(int fd, char *b, int l) { return syscall3(15, fd, (int)b, l); }
static int sys_write(int fd, const char *b, int l) { return syscall3(16, fd, (int)b, l); }
static int sys_close(int fd) { return syscall3(17, fd, 0, 0); }
static int sys_lseek(int fd, int off, int wh) { return syscall3(18, fd, off, wh); }
static int sys_pipe(int *f) { return syscall3(19, (int)f, 0, 0); }
static int sys_brk(int a) { return syscall3(20, a, 0, 0); }

static int eq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

int main(void) {
    int bad = 0;
    /* File fds: create, write, seek, read back. */
    int fd = sys_open("fdtest.txt", 0x41); /* WRONLY|CREAT */
    if (fd < 0) { sys_print("fdtest: open create FAIL\n"); bad = 1; }
    else {
        if (sys_write(fd, "hello-fd", 8) != 8) { sys_print("fdtest: write FAIL\n"); bad = 1; }
        sys_close(fd);
    }
    fd = sys_open("fdtest.txt", 0); /* RDONLY */
    if (fd < 0) { sys_print("fdtest: open read FAIL\n"); bad = 1; }
    else {
        char buf[16];
        for (int i = 0; i < 16; i++) buf[i] = 0;
        if (sys_read(fd, buf, 8) != 8 || !eq(buf, "hello-fd")) {
            sys_print("fdtest: read back FAIL\n"); bad = 1;
        }
        if (sys_lseek(fd, 2, 0) != 2) { sys_print("fdtest: lseek FAIL\n"); bad = 1; }
        for (int i = 0; i < 16; i++) buf[i] = 0;
        if (sys_read(fd, buf, 3) != 3 || !eq(buf, "llo")) {
            sys_print("fdtest: read after seek FAIL\n"); bad = 1;
        }
        sys_close(fd);
    }
    /* Anonymous pipe: write then read back in one program. */
    int pf[2];
    if (sys_pipe(pf) != 0) { sys_print("fdtest: pipe FAIL\n"); bad = 1; }
    else {
        /* Only read when the write succeeded: reading an empty
           pipe with a live writer blocks, by design. */
        if (sys_write(pf[1], "pipedata", 8) != 8) { sys_print("fdtest: pipe write FAIL\n"); bad = 1; }
        else {
            char buf[16];
            for (int i = 0; i < 16; i++) buf[i] = 0;
            if (sys_read(pf[0], buf, 8) != 8 || !eq(buf, "pipedata")) {
                sys_print("fdtest: pipe read FAIL\n"); bad = 1;
            }
        }
        sys_close(pf[0]); sys_close(pf[1]);
    }
    /* brk: grow the heap, write every new page, read back. */
    int base = sys_brk(0);
    if (base <= 0) { sys_print("fdtest: brk query FAIL\n"); bad = 1; }
    else {
        int end = sys_brk(base + 8192);
        if (end != base + 8192) { sys_print("fdtest: brk grow FAIL\n"); bad = 1; }
        else {
            char *hp = (char *)base;
            for (int i = 0; i < 8192; i++) hp[i] = (char)(i & 0x7F);
            int ok = 1;
            for (int i = 0; i < 8192; i++) if (hp[i] != (char)(i & 0x7F)) { ok = 0; break; }
            if (!ok) { sys_print("fdtest: brk memory FAIL\n"); bad = 1; }
        }
    }
    (void)sys_ticks;
    if (bad) { sys_print("fdtest: FAIL\n"); return 1; }
    sys_print("fdtest: PASS\n");
    return 0;
}
