/* nxtsOS benchmark package (6(c) package-ecosystem growth):
   a real, small system utility, not a stub. It runs a fixed
   deterministic workload in rounds until at least 20 timer
   ticks have elapsed, then prints the rounds completed, the
   elapsed ticks, and a checksum of the work. The checksum
   proves the loop really ran (a program that only printed
   would have nothing to checksum), and the rounds/ticks
   pair is a comparable CPU-speed figure across builds and
   machines. No libc, no division or modulo (the user
   program is linked without libgcc): number printing is
   subtraction against a table of powers of ten, like
   hello.c's uid print. It takes no arguments: user
   programs receive none (the _start stub calls main with
   no argv), so the workload size is fixed by design.
   Run from the shell with `run bench.elf` after
   installing the bench package. */
static int syscall1(int num, int a1) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall1(1, (int)s); }
static int sys_ticks(void) { return syscall1(5, 0); }

/* Print an unsigned 32-bit value, no division: walk the
   powers of ten from large to small, subtracting. */
static void print_u32(unsigned int v) {
    static const unsigned int powers[10] =
        { 1000000000u, 100000000u, 10000000u, 1000000u, 100000u,
          10000u, 1000u, 100u, 10u, 1u };
    char buf[12];
    int i = 0, k, started = 0;
    if (v == 0) { sys_print("0"); return; }
    for (k = 0; k < 10; k++) {
        unsigned int d = 0;
        while (v >= powers[k]) { v -= powers[k]; d++; }
        if (d || started) { buf[i++] = (char)('0' + d); started = 1; }
    }
    buf[i] = 0;
    sys_print(buf);
}

/* One round of deterministic work; returns the updated
   checksum. Kept small so the tick loop, not one round,
   sets the measurement granularity. */
static unsigned int work_round(unsigned int sum) {
    unsigned int i;
    for (i = 0; i < 20000u; i++) {
        sum = sum * 33u + i;
        sum = sum ^ (sum >> 13u);
    }
    return sum;
}

int main(void) {
    int t0 = sys_ticks();
    int elapsed = 0, rounds = 0;
    unsigned int sum = 0;
    while (elapsed < 20 && rounds < 1000) {
        sum = work_round(sum);
        rounds++;
        elapsed = sys_ticks() - t0;
    }
    sys_print("bench: ");
    print_u32((unsigned int)rounds);
    sys_print(" rounds in ");
    print_u32((unsigned int)elapsed);
    sys_print(" ticks, checksum ");
    print_u32(sum);
    sys_print("\n");
    return 0;
}
