/* nxtsOS user test program: prints pid + iteration, then either yields
   (pid 1) or busy-loops (pid 2, to prove timer preemption). No libc:
   syscalls go straight through int 0x80. */
static int syscall2(int num, int a1) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall2(1, (int)s); }
static int sys_yield(void) { return syscall2(2, 0); }
static int sys_getpid(void) { return syscall2(4, 0); }
static int sys_ticks(void) { return syscall2(5, 0); }

int main(void) {
    int pid = sys_getpid();
    char buf[16];
    for (int i = 0; i < 5; i++) {
        buf[0] = 'P'; buf[1] = (char)('0' + pid); buf[2] = ' ';
        buf[3] = 'i'; buf[4] = 't'; buf[5] = 'e'; buf[6] = 'r'; buf[7] = ' ';
        buf[8] = (char)('0' + i); buf[9] = '\n'; buf[10] = 0;
        sys_print(buf);
        if (pid == 1) {
            sys_yield();
        } else {
            /* v0.4.1: was 50,000,000 iterations x 5 = 250M, which took
               tens of seconds on a slower QEMU host and delayed the
               shell prompt, while 5,000,000 iterations finished in
               under one 100 ms quantum on a fast host and proved
               nothing about preemption. Time-based instead: busy-wait
               30 ticks (300 ms) per iteration, which is always over
               the 100 ms timer quantum regardless of host speed, so
               P1 prints still interleave during P2's busy loop, and
               the whole startup test takes ~1.5 s on any host. */
            int start = sys_ticks();
            while (sys_ticks() - start < 30) { }
        }
    }
    return 0;
}
