/* nxtsOS package upgrade test program: same package name and filename
   as hello.elf, but version 1.1 content, so an upgrade is visible. */
static int syscall2(int num, int a1) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall2(1, (int)s); }
int main(void) { sys_print("Hello v1.1\n"); return 0; }
