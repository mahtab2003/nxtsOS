/* Deep-core D2 test program: open a FIFO for writing (pairs
   with a waiting reader), write a message, close, exit 0.
   No libc: syscalls go straight through int 0x80. */
static int syscall3(int num, int a1, int a2, int a3) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1), "c"(a2), "d"(a3) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall3(1, (int)s, 0, 0); }
static int sys_open(const char *n, int f) { return syscall3(14, (int)n, f, 0); }
static int sys_write(int fd, const char *b, int l) { return syscall3(16, fd, (int)b, l); }
static int sys_close(int fd) { return syscall3(17, fd, 0, 0); }

int main(void) {
    int fd = sys_open("testfifo", 1); /* WRONLY: blocks until a reader opens */
    if (fd < 0) { sys_print("fifowriter: open FAIL\n"); return 1; }
    if (sys_write(fd, "hello-fifo\n", 11) != 11) {
        sys_print("fifowriter: write FAIL\n"); sys_close(fd); return 1;
    }
    sys_close(fd);
    sys_print("fifowriter: done\n");
    return 0;
}
