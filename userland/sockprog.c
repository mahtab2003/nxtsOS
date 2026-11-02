/* §15.2 user-program socket test: socket/connect/write/read/
   close through syscalls 22/26/16/15/17 against the peer's
   echo server (192.168.99.1:18082, replies ACK+payload).
   Prints sockprog: OK only if the reply matches exactly.
   No libc: syscalls go straight through int 0x80. */
static int syscall3(int num, int a1, int a2, int a3) {
    int ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(num), "b"(a1), "c"(a2), "d"(a3) : "memory");
    return ret;
}
static int sys_print(const char *s) { return syscall3(1, (int)s, 0, 0); }
static int sys_socket(int fam, int type) { return syscall3(22, fam, type, 0); }
static int sys_connect(int fd, unsigned ip, int port) { return syscall3(26, fd, (int)ip, port); }
static int sys_read(int fd, char *b, int l) { return syscall3(15, fd, (int)b, l); }
static int sys_write(int fd, const char *b, int l) { return syscall3(16, fd, (int)b, l); }
static int sys_close(int fd) { return syscall3(17, fd, 0, 0); }

int main(void) {
    /* 192.168.99.1 in network byte order. */
    unsigned peer = (192u << 24) | (168u << 16) | (99u << 8) | 1u;
    int fd = sys_socket(2, 1);
    if (fd < 0) { sys_print("sockprog: socket FAIL\n"); return 1; }
    if (sys_connect(fd, peer, 18082) != 0) {
        sys_print("sockprog: connect FAIL\n");
        sys_close(fd);
        return 1;
    }
    if (sys_write(fd, "PROG-HELLO", 10) != 10) {
        sys_print("sockprog: write FAIL\n");
        sys_close(fd);
        return 1;
    }
    /* Socket reads are poll-based: 0 means no data yet.
       Each read polls the NIC once, so a bounded busy loop
       is the wait. */
    char buf[32];
    int n = 0;
    for (int i = 0; i < 200000 && n <= 0; i++) {
        n = sys_read(fd, buf, 14);
        if (n < 0) break;
    }
    if (n != 14) {
        sys_print("sockprog: recv FAIL\n");
        sys_close(fd);
        return 1;
    }
    const char *want = "ACK-PROG-HELLO";
    for (int i = 0; i < 14; i++) {
        if (buf[i] != want[i]) {
            sys_print("sockprog: reply mismatch\n");
            sys_close(fd);
            return 1;
        }
    }
    sys_print("sockprog: OK\n");
    sys_close(fd);
    return 0;
}
