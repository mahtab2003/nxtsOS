/* Deep-core D2 test program: against flocklock's hold, a
   non-blocking exclusive lock must fail, then a blocking
   exclusive lock must succeed once the holder releases.
   No libc: syscalls go straight through int 0x80. */
static int syscall3(int num, int a1, int a2, int a3) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1), "c"(a2), "d"(a3) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall3(1, (int)s, 0, 0); }
static int sys_open(const char *n, int f) { return syscall3(14, (int)n, f, 0); }
static int sys_close(int fd) { return syscall3(17, fd, 0, 0); }
static int sys_flock(int fd, int op) { return syscall3(21, fd, op, 0); }

int main(void) {
    int fd = sys_open("lockfile.txt", 1); /* WRONLY */
    if (fd < 0) { sys_print("flocktry: open FAIL\n"); return 1; }
    if (sys_flock(fd, 2 | 4) == 0) { /* EX|NB must fail while held */
        sys_print("flocktry: NB lock unexpectedly succeeded\n");
        sys_close(fd); return 1;
    }
    sys_print("flocktry: NB would block\n");
    if (sys_flock(fd, 2) != 0) { /* blocking EX: waits for release */
        sys_print("flocktry: blocking lock FAIL\n"); sys_close(fd); return 1;
    }
    sys_print("flocktry: got lock\n");
    sys_flock(fd, 8);
    sys_close(fd);
    return 0;
}
