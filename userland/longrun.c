/* nxtsOS background-job test program: like slow.c but ~60 s
   long, so multi-step job-control tests (top k, kill %N,
   killall) never race its exit. No libc: syscalls go
   straight through int 0x80. */
static int syscall2(int num, int a1) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall2(1, (int)s); }
static int sys_yield(void) { return syscall2(2, 0); }
static int sys_ticks(void) { return syscall2(5, 0); }

int main(void) {
    sys_print("longrun start\n");
    for (int i = 0; i < 60; i++) {
        /* 100 ticks (1 s) per iteration, same shape as slow.c. */
        int start = sys_ticks();
        while (sys_ticks() - start < 100) { }
        sys_yield();
    }
    sys_print("longrun done\n");
    return 0;
}
