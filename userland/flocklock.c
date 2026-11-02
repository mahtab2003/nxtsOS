/* Deep-core D2 test program: hold an exclusive flock on a
   file for ~5 seconds, then release it. The contender program
   proves blocking + NB failure against this hold.
   No libc: syscalls go straight through int 0x80. */
static int syscall3(int num, int a1, int a2, int a3) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1), "c"(a2), "d"(a3) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall3(1, (int)s, 0, 0); }
static int sys_ticks(void) { return syscall3(5, 0, 0, 0); }
static int sys_yield(void) { return syscall3(2, 0, 0, 0); }
static int sys_open(const char *n, int f) { return syscall3(14, (int)n, f, 0); }
static int sys_close(int fd) { return syscall3(17, fd, 0, 0); }
static int sys_flock(int fd, int op) { return syscall3(21, fd, op, 0); }

int main(void) {
    int fd = sys_open("lockfile.txt", 0x41); /* WRONLY|CREAT */
    if (fd < 0) { sys_print("flocklock: open FAIL\n"); return 1; }
    if (sys_flock(fd, 2) != 0) { sys_print("flocklock: lock FAIL\n"); sys_close(fd); return 1; }
    sys_print("flocklock: locked\n");
    int start = sys_ticks();
    while (sys_ticks() - start < 500) { sys_yield(); }
    if (sys_flock(fd, 8) != 0) { sys_print("flocklock: unlock FAIL\n"); sys_close(fd); return 1; }
    sys_print("flocklock: unlocked\n");
    sys_close(fd);
    return 0;
}
