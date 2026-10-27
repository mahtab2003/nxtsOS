/* nxtsOS GUI adversarial test program (Phase 8 security test).
   Runs from the text shell WITHOUT the desktop running, so every
   GUI syscall must be rejected: no desktop means no user window,
   and malformed arguments must be rejected by the syscall handler
   before any window code runs. Prints guibad PASS only if all
   calls return -1. No libc, int 0x80 only. */
static int syscall5(int num, int a1, int a2, int a3, int a4, int a5) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5) : "memory");
    return ret;
}
static int sys_print(const char *s) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(1), "b"((int)s), "c"(0), "d"(0) : "memory");
    return ret;
}
int main(void) {
    int bad = 0;
    /* Null title pointer. */
    if (syscall5(9, 0, 0, 0, 100, 100) != -1) bad++;
    /* Huge window (over the 4096 cap). */
    if (syscall5(9, (int)"Bad", 0, 0, 5000, 100) != -1) bad++;
    /* Rect with huge size, no window at all. */
    if (syscall5(10, 0, 0, 5000, 5000, 0) != -1) bad++;
    /* Text with a non-printable byte: build it on the stack so
       the pointer itself is valid, but the content is not. */
    char txt[4]; txt[0] = 'A'; txt[1] = 1; txt[2] = 0; txt[3] = 0;
    if (syscall5(11, 0, 0, 0, 0, (int)txt) != -1) bad++;
    /* Event read with a null output pointer. */
    if (syscall5(12, 0, 0, 0, 0, 0) != -1) bad++;
    /* Close with no window. */
    if (syscall5(13, 0, 0, 0, 0, 0) != -1) bad++;
    if (bad == 0) sys_print("guibad PASS (all GUI calls rejected)\n");
    else sys_print("guibad FAIL\n");
    return 0;
}
