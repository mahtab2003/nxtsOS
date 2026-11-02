/* Deep-core test program: exits with status 7, so the shell's
   wait/fg exit-status reporting has something real to report.
   No libc: syscalls go straight through int 0x80. */
static int syscall2(int num, int a1) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall2(1, (int)s); }

int main(void) {
    sys_print("exitcode start\n");
    return 7;
}
