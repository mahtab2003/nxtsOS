/* nxtsOS package test program: a second, independent ELF used as the
   payload of the "greet" package, which depends on "hello". */
static int syscall2(int num, int a1) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall2(1, (int)s); }
int main(void) { sys_print("Greetings from greet\n"); return 0; }
