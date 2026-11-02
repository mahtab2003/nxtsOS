/* Socket layer (CORE_CLI.md §15.2, redesign 3): a socket table
   of socket objects, one TCP state machine instance per
   connection, plus UDP sockets on the same table. The old
   single-connection TCP client (net/tcp.c) is a thin wrapper
   over this table now, not a parallel implementation.
   All state lives in file-scope statics in net/sock.c — never
   on the kernel stack (16 KiB). A socket index is a kernel
   object handle; user programs reach sockets through the §14
   fd table (PFD_SOCK), never by raw index.
   Return conventions: 0 ok, -1 fail, -2 refused for a
   permission reason (privileged port for a non-root uid).
   Socket I/O for user programs is poll-based: a read with
   no data yet returns 0 bytes (not a block — there is no
   per-socket wait queue yet, so parking a job in the RX path
   would need a new pend kind + wakeup; that is documented
   in §15.2 notes, not silently faked as blocking). A read
   returning -1 means the socket is closed, reset, or (for
   TCP) the peer has closed and the buffer is drained. */
#ifndef NXTS_SOCK_H
#define NXTS_SOCK_H
#include "net.h"

#define SK_AF_INET 2
#define SK_STREAM 1
#define SK_DGRAM 2

/* Socket states (§15.2). SYN_SENT is the client half of the
   handshake; CLOSE_WAIT means the peer sent FIN, we ACKed,
   and the receive buffer is still being drained. */
#define SK_CLOSED 0
#define SK_LISTEN 1
#define SK_SYN_SENT 2
#define SK_SYN_RCVD 3
#define SK_ESTABLISHED 4
#define SK_CLOSE_WAIT 5

#define SK_MAX 16
#define SK_BACKLOG_MAX 4
/* Receive buffer per socket. 4096, not 2048: the legacy client
   used a 4096-byte buffer with a 4096-byte window, and that
   batching is what makes bursty (slirp) senders flow — a
   2048-byte buffer with a dynamic window stalled a 20 KB slirp
   fetch at 3373 bytes in the fast path (paced transfers and
   the raw-peer lock-step path were unaffected, and the guest
   TCP logic itself was proven correct: 0 gap/partial drops,
   valid checksums). With the dynamic-window fix the window
   still never exceeds the buffer, so the 4096/4096 invariant
   of the legacy client is restored, plus straddle-take and
   drain window-update robustness. Table cost: 16 x 4096. */
#define SK_RX_SIZE 4096u
#define SK_MAX_SEG 1400u

int  sock_alloc(int type, int *idx_out); /* -1 table full */
void sock_free(int idx); /* frees, closing a listener's pending children first */
int  sock_bind(int idx, ip_t addr, u16 port, u32 uid); /* 0, -1, -2 priv */
int  sock_listen(int idx, int backlog, u32 uid); /* 0, -1, -2 priv */
int  sock_accept(int idx, int *child_out); /* 0, -1 none pending */
int  sock_connect(int idx, ip_t dst, u16 port); /* TCP handshake, or UDP peer set */
int  sock_tcp_send(int idx, const u8 *data, u32 len); /* 0 sent+ACKed */
int  sock_tcp_recv(int idx, u8 *buf, u32 max, u32 timeout_ticks);
/* bytes, 0 = timeout slice (still open), -1 = closed/reset */
int  sock_tcp_recv_nb(int idx, u8 *buf, u32 max, u32 *done_out);
/* 0 ok (done may be 0), -1 closed/reset */
void sock_close(int idx); /* FIN (STREAM, when established) + free */
int  sock_udp_send(int idx, ip_t dst, u16 dport, const u8 *data, u32 len);
int  sock_udp_send_connected(int idx, const u8 *data, u32 len);
int  sock_udp_recv(int idx, u8 *buf, u32 max, ip_t *src_out, u16 *sport_out,
                   u32 timeout_ticks); /* bytes, 0 timeout, -1 fail */
int  sock_udp_recv_nb(int idx, u8 *buf, u32 max, ip_t *src_out, u16 *sport_out,
                      u32 *done_out); /* 0 ok (done may be 0), -1 fail */
/* RX dispatch (called from the stack's receive path, after the
   inbound firewall check in net_rx_frame — server sockets are
   filtered exactly like client traffic, never exempt). */
void sock_tcp_rx(const u8 *ip, u32 ip_len, ip_t src);
int  sock_udp_rx_dispatch(const u8 *ip, u32 ip_len, ip_t src); /* 1 consumed */
void sock_dump(void); /* `srv status`: one line per used socket */
int  sock_state(int idx); /* SK_* or -1 */
int  sock_type(int idx); /* SK_STREAM / SK_DGRAM, or -1 */
u16  sock_local_port(int idx);
int  sock_pending_count(int idx);

#endif
