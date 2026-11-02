/* nxtsOS demand-paging test program (redesign 5, CORE_CLI.md
   section 15.4): register a 2-page VMA, prove the first
   access to each page faults in a zero page (read 0, write
   + read back), then touch an address outside every VMA.
   That last access must terminate this process (SIGSEGV,
   status 139) while the kernel and shell survive — the
   "bad access SURVIVED" line must never print. No libc:
   syscalls go straight through int 0x80. */
static int syscall2(int num, int a1) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1) : "memory");
    return ret;
}
static int syscall3(int num, int a1, int a2, int a3) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1), "c"(a2), "d"(a3) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall2(1, (int)s); }
static int sys_vma_add(unsigned int addr, unsigned int pages, unsigned int flags) {
    return syscall3(29, (int)addr, (int)pages, (int)flags);
}

#define VMA_ADDR 0x02000000u

int main(void) {
    sys_print("pagetest start\n");
    if (sys_vma_add(VMA_ADDR, 2, 1) != 0) {
        sys_print("pagetest: vma FAILED\n");
        return 1;
    }
    sys_print("pagetest: vma ok\n");
    volatile unsigned int *p0 = (volatile unsigned int *)VMA_ADDR;
    if (p0[0] != 0) {
        sys_print("pagetest: zero page FAILED\n");
        return 1;
    }
    sys_print("pagetest: zero page ok\n");
    p0[1] = 0x12345678u;
    if (p0[1] != 0x12345678u) {
        sys_print("pagetest: readback FAILED\n");
        return 1;
    }
    sys_print("pagetest: readback ok\n");
    volatile unsigned int *p1 = (volatile unsigned int *)(VMA_ADDR + 4096u);
    *p1 = 0xABCDEF01u;
    if (*p1 != 0xABCDEF01u) {
        sys_print("pagetest: second page FAILED\n");
        return 1;
    }
    sys_print("pagetest: second page ok\n");
    /* Outside every VMA (below USER_BASE, above the kernel
       region): this load must fault and terminate us. */
    volatile unsigned int *bad = (volatile unsigned int *)0x05000000u;
    unsigned int x = *bad;
    (void)x;
    sys_print("pagetest: bad access SURVIVED (BUG)\n");
    return 1;
}
