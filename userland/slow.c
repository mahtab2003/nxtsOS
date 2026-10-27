/* nxtsOS background-job test program: prints an iteration, yields, and
   repeats, so the shell prompt returns between iterations and `jobs`
   shows it still active. No libc: syscalls go straight through int 0x80. */
static int syscall2(int num, int a1) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall2(1, (int)s); }
static int sys_yield(void) { return syscall2(2, 0); }
static int sys_getuid(void) { return syscall2(6, 0); }
static int sys_ticks(void) { return syscall2(5, 0); }

static void print_uid(int uid) {
    /* Decimal, without division by a variable (no libgcc). */
    char out[16]; int n = 0;
    out[n++] = 's'; out[n++] = 'l'; out[n++] = 'o'; out[n++] = 'w';
    out[n++] = ' '; out[n++] = 'u'; out[n++] = 'i'; out[n++] = 'd';
    out[n++] = ' ';
    int thousands = 0, hundreds = 0, tens = 0;
    while (uid >= 1000) { uid -= 1000; thousands++; }
    while (uid >= 100) { uid -= 100; hundreds++; }
    while (uid >= 10) { uid -= 10; tens++; }
    if (thousands) out[n++] = (char)('0' + thousands);
    if (thousands || hundreds) out[n++] = (char)('0' + hundreds);
    if (thousands || hundreds || tens) out[n++] = (char)('0' + tens);
    out[n++] = (char)('0' + uid); out[n++] = '\n'; out[n++] = 0;
    sys_print(out);
}

int main(void) {
    sys_print("slow start\n");
    print_uid(sys_getuid());
    for (int i = 0; i < 5; i++) {
        char buf[16];
        buf[0] = 's'; buf[1] = 'l'; buf[2] = 'o'; buf[3] = 'w'; buf[4] = ' ';
        buf[5] = 'i'; buf[6] = 't'; buf[7] = 'e'; buf[8] = 'r'; buf[9] = ' ';
        buf[10] = (char)('0' + i); buf[11] = '\n'; buf[12] = 0;
        sys_print(buf);
        /* Time-based busy wait: 100 ticks (1 s) per iteration, so
           the job stays active for ~5 s on any host speed — long
           enough to type `jobs` and `kill` while it runs, short
           enough to finish on its own if not killed. Timer
           preemption also returns to the shell during the wait,
           so the prompt stays responsive throughout. */
        int start = sys_ticks();
        while (sys_ticks() - start < 100) { }
        sys_yield();
    }
    sys_print("slow done\n");
    return 0;
}
