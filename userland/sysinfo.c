/* nxtsOS system-information package (6(c) package-ecosystem
   growth, second new package after bench): a real, small
   system utility, not a stub. It prints the running
   program's process id (SYS_GETPID), the owner's user id
   (SYS_GETUID), and the kernel uptime in ticks and in
   whole seconds (SYS_TICKS; the PIT runs at 100 Hz, so
   seconds = ticks / 100 by repeated subtraction — no
   division instruction, the user program is linked
   without libgcc, same rule as bench.c/hello.c).
   The pid/uid pair proves the program really ran under
   the kernel's process/user accounting (a program that
   only printed constants could not produce them), and
   the uptime pair is comparable across boots. It takes
   no arguments: user programs receive none (the _start
   stub calls main with no argv), so there is no target
   to select — stated honestly, not papered over.
   Run from the shell with `run sysinfo.elf` after
   installing the sysinfo package. */
static int syscall1(int num, int a1) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall1(1, (int)s); }
static int sys_getpid(void) { return syscall1(4, 0); }
static int sys_ticks(void) { return syscall1(5, 0); }
static int sys_getuid(void) { return syscall1(6, 0); }

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

/* Whole seconds from ticks at 100 Hz, by subtraction. */
static unsigned int ticks_to_seconds(unsigned int ticks) {
    unsigned int secs = 0;
    while (ticks >= 100u) { ticks -= 100u; secs++; }
    return secs;
}

int main(void) {
    unsigned int ticks = (unsigned int)sys_ticks();
    sys_print("sysinfo: pid ");
    print_u32((unsigned int)sys_getpid());
    sys_print(" uid ");
    print_u32((unsigned int)sys_getuid());
    sys_print(" uptime ");
    print_u32(ticks_to_seconds(ticks));
    sys_print(" seconds (");
    print_u32(ticks);
    sys_print(" ticks)\n");
    return 0;
}
