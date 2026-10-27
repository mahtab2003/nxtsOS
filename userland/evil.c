/* Malicious-user test program: tries to abuse syscalls with kernel
   pointers. The kernel must reject every attempt with -1 and keep
   running; the program reports each rejection. */
static int syscall3(int num, int a1, int a2, int a3) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1), "c"(a2), "d"(a3) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall3(1, (int)s, 0, 0); }
static int sys_read_file(const char *name, char *buf, int size) {
    return syscall3(7, (int)name, (int)buf, size);
}
static int sys_write_file(const char *name, const char *data, int len) {
    return syscall3(8, (int)name, (int)data, len);
}

int main(void) {
    char buf[64];
    sys_print("evil: starting\n");
    if (sys_print((const char *)0x00100000) < 0)
        sys_print("evil print rejected\n");
    else
        sys_print("evil print ACCEPTED BAD\n");
    if (sys_read_file((const char *)0x00100000, buf, 64) < 0)
        sys_print("evil filename rejected\n");
    else
        sys_print("evil filename ACCEPTED BAD\n");
    if (sys_read_file("public.txt", (char *)0x00100000, 64) < 0)
        sys_print("evil buffer rejected\n");
    else
        sys_print("evil buffer ACCEPTED BAD\n");
    if (sys_read_file("public.txt", (char *)0, 64) < 0)
        sys_print("evil null buffer rejected\n");
    else
        sys_print("evil null buffer ACCEPTED BAD\n");
    if (sys_write_file("public.txt", (const char *)0x00100000, 4) < 0)
        sys_print("evil write buffer rejected\n");
    else
        sys_print("evil write buffer ACCEPTED BAD\n");
    sys_print("evil: done, kernel survived\n");
    return 0;
}
