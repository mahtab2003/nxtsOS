/* nxtsOS ELF test program (loaded from disk by the Phase 5 loader):
   prints a greeting, its uid, tries to read a public and a private
   file via syscalls, and tries to write a file. No libc: syscalls
   go straight through int 0x80. No division is used (the user program
   is linked without libgcc), so uid printing uses subtraction. */
static int syscall3(int num, int a1, int a2, int a3) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1), "c"(a2), "d"(a3) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall3(1, (int)s, 0, 0); }
static int sys_getuid(void) { return syscall3(6, 0, 0, 0); }
static int sys_read_file(const char *name, char *buf, int size) {
    return syscall3(7, (int)name, (int)buf, size);
}
static int sys_write_file(const char *name, const char *data, int len) {
    return syscall3(8, (int)name, (int)data, len);
}
static void print_uid(int uid) {
    char buf[8];
    int i = 0;
    int thousands = 0, hundreds = 0, tens = 0, ones = 0;
    while (uid >= 1000) { uid -= 1000; thousands++; }
    while (uid >= 100) { uid -= 100; hundreds++; }
    while (uid >= 10) { uid -= 10; tens++; }
    ones = uid;
    if (thousands) buf[i++] = (char)('0' + thousands);
    if (thousands || hundreds) buf[i++] = (char)('0' + hundreds);
    if (thousands || hundreds || tens) buf[i++] = (char)('0' + tens);
    buf[i++] = (char)('0' + ones);
    buf[i++] = '\n'; buf[i] = 0;
    sys_print(buf);
}
static int my_strlen(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

int main(void) {
    char buf[128];
    sys_print("Hello from ELF\n");
    sys_print("uid: ");
    print_uid(sys_getuid());
    int n = sys_read_file("public.txt", buf, 127);
    if (n >= 0) { buf[n] = 0; sys_print("public: "); sys_print(buf); sys_print("\n"); }
    else sys_print("public: access denied\n");
    n = sys_read_file("secret.txt", buf, 127);
    if (n >= 0) { buf[n] = 0; sys_print("secret: "); sys_print(buf); sys_print("\n"); }
    else sys_print("secret: access denied\n");
    const char *note = "written by ELF\n";
    if (sys_write_file("elfnote.txt", note, my_strlen(note)) == 0)
        sys_print("elf write ok\n");
    else
        sys_print("elf write denied\n");
    return 0;
}
