/* Deep-core D2 test program: open a FIFO for reading (blocks
   until a writer opens), read the message, print it, exit 0.
   No libc: syscalls go straight through int 0x80. */
static int syscall3(int num, int a1, int a2, int a3) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1), "c"(a2), "d"(a3) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall3(1, (int)s, 0, 0); }
static int sys_open(const char *n, int f) { return syscall3(14, (int)n, f, 0); }
static int sys_read(int fd, char *b, int l) { return syscall3(15, fd, (int)b, l); }
static int sys_close(int fd) { return syscall3(17, fd, 0, 0); }

int main(void) {
    int fd = sys_open("testfifo", 0); /* RDONLY: blocks until a writer opens */
    if (fd < 0) { sys_print("fiforeader: open FAIL\n"); return 1; }
    char buf[32];
    for (int i = 0; i < 32; i++) buf[i] = 0;
    int n = sys_read(fd, buf, 31);
    sys_close(fd);
    if (n != 11) { sys_print("fiforeader: read FAIL\n"); return 1; }
    sys_print("fiforeader: got ");
    sys_print(buf);
    return 0;
}
