/* Deep-core D2 test program (run as bob): opening an admin
   600 file must fail, creating/using an own file must work.
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
    int bad = 0;
    if (sys_open("secret.txt", 0) >= 0) {
        sys_print("permtest: secret open unexpectedly succeeded\n"); bad = 1;
    } else {
        sys_print("permtest: secret denied\n");
    }
    int fd = sys_open("bobfile.txt", 0x41); /* WRONLY|CREAT */
    if (fd < 0) { sys_print("permtest: own create FAIL\n"); bad = 1; }
    else {
        if (sys_write(fd, "bobdata", 7) != 7) { sys_print("permtest: own write FAIL\n"); bad = 1; }
        sys_close(fd);
        sys_print("permtest: own file ok\n");
    }
    if (bad) { sys_print("permtest: FAIL\n"); return 1; }
    sys_print("permtest: PASS\n");
    return 0;
}
