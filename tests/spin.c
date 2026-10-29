/* Test-only background job for qemu_test_webpanic_desktop.py: yields
   forever, never exits, prints nothing. Keeps a user page directory
   active while the desktop fetches, so a missing kernel-PD restore
   (the v1.1.2 Web-open panic) would fault. No libc: syscalls go
   straight through int 0x80. Not built by scripts/build.sh. */
static int sys_yield(void) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(2), "b"(0) : "memory");
    return ret;
}
int main(void) { for (;;) sys_yield(); return 0; }
