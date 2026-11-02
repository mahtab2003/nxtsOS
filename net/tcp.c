/* Legacy TCP client API (net_tcp_*), kept for HTTP/HTTPS:
   it is now a thin wrapper over ONE socket-table entry
   (net/sock.c), not a parallel stack. The single-connection
   semantics are preserved exactly (one legacy handle at a
   time; a new connect closes the old one first), while
   other sockets in the table proceed concurrently — the
   table, not this wrapper, is what concurrent clients and
   servers use. Known limits live with the table now (see
   net/sock.c): predictable sequence numbers, fixed-timer
   retransmission. */
#include "sock.h"

static int legacy_sock = -1;

int net_tcp_connected(void) {
    return legacy_sock >= 0 && sock_state(legacy_sock) == SK_ESTABLISHED;
}



int net_tcp_connect(ip_t dst, u16 port) {
    if (legacy_sock >= 0) {
        sock_close(legacy_sock);
        legacy_sock = -1;
    }
    int idx;
    if (sock_alloc(SK_STREAM, &idx) != 0) return -1;
    if (sock_connect(idx, dst, port) != 0) {
        sock_free(idx);
        return -1;
    }
    legacy_sock = idx;
    return 0;
}

int net_tcp_send(const u8 *data, u32 len) {
    if (legacy_sock < 0) return -1;
    return sock_tcp_send(legacy_sock, data, len);
}

int net_tcp_recv(u8 *buf, u32 max, u32 timeout_ticks) {
    if (legacy_sock < 0) return -1;
    return sock_tcp_recv(legacy_sock, buf, max, timeout_ticks);
}

void net_tcp_close(void) {
    if (legacy_sock >= 0) {
        sock_close(legacy_sock);
        legacy_sock = -1;
    }
}
