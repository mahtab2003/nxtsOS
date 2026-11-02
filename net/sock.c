/* Socket layer (CORE_CLI.md §15.2): the socket table.
   One TCP state machine instance per socket; the old
   single-connection client is a wrapper over this table
   (net/tcp.c), not a second implementation. Server sockets
   never share state with client sockets: an accepted
   connection is a fresh socket whose listener field is
   cleared on accept, and a listener's pending queue holds
   child indices, never shared buffers.
   Stack note: the TCP segment buffer is a stack array of
   1500 bytes, exactly as the legacy client had it (the
   send path is never re-entered inside itself — ARP
   resolution polls, but a nested RX only verifies into the
   file-scope verify buffer below, then sends from its own
   stack frame). The checksum-verify buffer IS file-scope
   static: verification always completes before any send
   in the same frame, so a nested RX reusing it is safe.
   Known limits, stated plainly (carried from the legacy
   client): sequence numbers derive from the timer plus a
   counter (predictable — not safe against a hostile
   on-path attacker in production); retransmission is a
   single fixed timer, not exponential backoff; the UDP
   receive queue holds ONE datagram (a second datagram
   arriving before the first is read is dropped, and the
   drop is counted by the stack, not silently queued);
   socket reads for user programs are poll-based (see
   sock.h), not blocking. */
#include "sock.h"
#include "../drivers/pit.h"

static void sput16(u8 *p, u16 v) { p[0] = (u8)(v >> 8); p[1] = (u8)v; }
static void sput32(u8 *p, u32 v) {
    p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16); p[2] = (u8)(v >> 8); p[3] = (u8)v;
}
static u16 sget16(const u8 *p) { return (u16)(((u16)p[0] << 8) | p[1]); }
static u32 sget32(const u8 *p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}
static const char *sk_state_name(int st) {
    switch (st) {
    case SK_CLOSED: return "CLOSED";
    case SK_LISTEN: return "LISTEN";
    case SK_SYN_SENT: return "SYN-SENT";
    case SK_SYN_RCVD: return "SYN-RCVD";
    case SK_ESTABLISHED: return "ESTABLISHED";
    case SK_CLOSE_WAIT: return "CLOSE-WAIT";
    default: return "?";
    }
}

struct sock {
    int used;
    int type; /* SK_STREAM / SK_DGRAM */
    int state;
    int bound; /* bind() done (either family) */
    int udp_connected; /* DGRAM only: connect() set a peer */
    ip_t local_ip;
    u16 local_port;
    ip_t remote_ip;
    u16 remote_port;
    int listener; /* child of a listener: its index, else -1 */
    int pend[SK_BACKLOG_MAX];
    int pend_n;
    int backlog_cap; /* LISTEN only: clamped requested backlog */
    /* Per-connection TCP state. */
    u32 iss, snd_una, snd_nxt, rcv_nxt;
    int peer_closed;
    u32 last_syn_tick;
    union {
        struct { u8 buf[SK_RX_SIZE]; u32 len; } tcp;
        struct { u8 buf[SK_RX_SIZE]; u32 len; ip_t src; u16 sport; } udp;
    } rx;
};
static struct sock socks[SK_MAX];
static u8 sock_vbuf[1500]; /* checksum-verify scratch, see header comment */
static u16 next_ephem = 49152;
static u32 iss_counter = 0;
/* Diagnostic counters for the multi-KB slirp stall (reset at
   each client connect / server-child spawn, printed at close).
   Cumulative over one connection only; cheap (no per-segment
   serial output, which would distort timing). */
static u32 dbg_rxseg, dbg_rxtake, dbg_gapdrop, dbg_partial, dbg_straddle;
static u32 dbg_acksent, dbg_drain, dbg_drainfull;
static void dbg_reset(void) {
    dbg_rxseg = dbg_rxtake = dbg_gapdrop = dbg_partial = dbg_straddle = 0;
    dbg_acksent = dbg_drain = dbg_drainfull = 0;
}

static struct sock *sk_get(int idx) {
    if (idx < 0 || idx >= SK_MAX) return 0;
    if (!socks[idx].used) return 0;
    return &socks[idx];
}

static int port_in_use(int type, u16 port, int except_idx) {
    for (int i = 0; i < SK_MAX; i++) {
        if (i == except_idx) continue;
        if (!socks[i].used || !socks[i].bound) continue;
        if (socks[i].type != type) continue;
        if (socks[i].local_port == port) return 1;
    }
    return 0;
}

static u16 ephem_alloc(int type) {
    for (int tries = 0; tries < 10000; tries++) {
        u16 p = next_ephem;
        next_ephem++;
        if (next_ephem >= 60000) next_ephem = 49152;
        if (!port_in_use(type, p, -1)) return p;
    }
    return 0;
}

static u16 tcp_checksum(ip_t src, ip_t dst, const u8 *seg, u32 seg_len) {
    u8 pseudo[12];
    memcpy(pseudo, src.b, 4);
    memcpy(pseudo + 4, dst.b, 4);
    pseudo[8] = 0; pseudo[9] = 6;
    sput16(pseudo + 10, (u16)seg_len);
    u32 sum = 0;
    for (u32 i = 0; i + 1 < 12; i += 2) sum += ((u32)pseudo[i] << 8) | pseudo[i + 1];
    for (u32 i = 0; i + 1 < seg_len; i += 2) sum += ((u32)seg[i] << 8) | seg[i + 1];
    if (seg_len & 1) sum += (u32)seg[seg_len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (u16)(~sum & 0xFFFF);
}

/* Send one segment from this socket's own state. The caller
   owns snd_nxt semantics (SYN: seq == iss; data: seq ==
   snd_nxt, advanced by the caller after the send). */
/* Transmit segment scratch (file-scope static, NEVER a stack
   array: sock_send_seg sits at the bottom of a deep chain —
   shell -> pkg -> https -> TLS handshake (msg[2048] in
   tls_send_hs) -> net_ip_send (pkt[1420]) -> eth_send
   (frame[1514]) — and the three 1.4-1.5 KiB stack buffers
   together overflowed the 16 KiB kernel stack on the
   deeper pkg-install chain (but not the shallower
   pkg-update chain), writing the Ethernet frame over the
   .data word just below the stack bottom (legacy_sock),
   which killed the install handshake's CCS send with a
   garbage socket index. The buffer is scratch only: it is
   fully consumed by net_ip_send/net_send (copied to the
   TX ring) before sock_send_seg returns, so a nested
   send from the ACK wait cannot corrupt an in-flight
   segment. */
static u8 sock_txseg_buf[1500];

static int sock_send_seg(struct sock *s, u8 flags, const u8 *data, u32 len, int with_mss) {
    u8 *seg = sock_txseg_buf;
    /* NOTE: sizeof(seg) is the pointer size here (seg is a
       pointer to the static buffer), NOT the buffer size —
       use sizeof(sock_txseg_buf) explicitly. */
    if (20 + (with_mss ? 4 : 0) + len > sizeof(sock_txseg_buf)) return -1;
    ip_t mine; net_ip_addr(&mine);
    sput16(seg, s->local_port);
    sput16(seg + 2, s->remote_port);
    sput32(seg + 4, s->snd_nxt);
    sput32(seg + 8, s->rcv_nxt);
    u32 hlen = 20 + (with_mss ? 4 : 0);
    seg[12] = (u8)((hlen / 4) << 4);
    seg[13] = flags;
    /* Window: the ACTUAL free room in this socket's receive
       buffer, never a constant. The legacy client advertised
       4096 with a 4096-byte buffer (window == buffer, so the
       peer could never run ahead of the buffer). The table
       refactor first halved the buffer to 2048 but kept the
       4096 advertisement: a bursty peer then sent up to 4096
       bytes while only 2048 fit, the receiver took a segment
       partially (rcv_nxt mid-segment), and the peer's
       whole-segment retransmits were rejected as gaps
       (seq != rcv_nxt) — wedging the connection until the
       reader's deadline, truncating every multi-KB download
       (desktop_web 6029/7053 of 20000, repo sysinfo 6144 of
       6271, both PASS on the pre-socket baseline). Advertising
       room restores the invariant: the peer can never send
       more than the buffer holds. The buffer itself is back
       at 4096 (see SK_RX_SIZE): with a 2048-byte buffer the
       dynamic window alone fixed the shell repo path but a
       20 KB slirp burst still stalled at 3373 bytes in the
       fast path (paced transfers flowed), so the legacy
       4096/4096 batching is restored as well. */
    u32 room = s->rx.tcp.len < SK_RX_SIZE ? SK_RX_SIZE - s->rx.tcp.len : 0;
    sput16(seg + 14, (u16)room); /* window */
    sput16(seg + 16, 0);
    sput16(seg + 18, 0);
    if (with_mss) {
        seg[20] = 2; seg[21] = 4; sput16(seg + 22, 1460);
    }
    if (len > 0) memcpy(seg + hlen, data, len);
    sput16(seg + 16, tcp_checksum(mine, s->remote_ip, seg, hlen + len));
    if (net_ip_send(s->remote_ip, 6, seg, hlen + len) != 0) {
        return -1;
    }
    return 0;
}

static void sock_send_ack(struct sock *s) {
    dbg_acksent++;
    (void)sock_send_seg(s, 0x10, 0, 0, 0);
}

int sock_alloc(int type, int *idx_out) {
    if (type != SK_STREAM && type != SK_DGRAM) return -1;
    for (int i = 0; i < SK_MAX; i++) {
        if (socks[i].used) continue;
        memset(&socks[i], 0, sizeof(socks[i]));
        socks[i].used = 1;
        socks[i].type = type;
        socks[i].state = SK_CLOSED;
        socks[i].listener = -1;
        *idx_out = i;
        return 0;
    }
    return -1;
}

static void sock_unqueue(struct sock *child) {
    if (child->listener < 0) return;
    struct sock *l = sk_get(child->listener);
    if (!l) { child->listener = -1; return; }
    for (int i = 0; i < l->pend_n; i++) {
        if (l->pend[i] == (int)(child - socks)) {
            for (int j = i + 1; j < l->pend_n; j++) l->pend[j - 1] = l->pend[j];
            l->pend_n--;
            break;
        }
    }
    child->listener = -1;
}

void sock_free(int idx) {
    struct sock *s = sk_get(idx);
    if (!s) return;
    if (s->state == SK_LISTEN) {
        /* A listener going away takes ALL of its children
           with it: queued (ESTABLISHED, unaccepted) AND
           half-open (SYN-RCVD, handshake never completed).
           The half-open case matters: without it, a peer
           that SYNs and never ACKs leaves a child holding
           the port forever, and the next bind of that port
           fails with "already in use" (caught by the
           sockets suite: a leaked SYN-RCVD child blocked
           the firewall test's re-serve). Accepted children
           were already detached (listener == -1) and
           survive. Indices are collected first (small
           stack array, 64 bytes) because freeing mutates
           the table being scanned. */
        int kids[SK_MAX];
        int nkids = 0;
        while (s->pend_n > 0) {
            int c = s->pend[0];
            for (int j = 1; j < s->pend_n; j++) s->pend[j - 1] = s->pend[j];
            s->pend_n--;
            kids[nkids++] = c;
        }
        for (int i = 0; i < SK_MAX; i++) {
            if (socks[i].used && socks[i].listener == idx)
                kids[nkids++] = i;
        }
        for (int k = 0; k < nkids; k++) {
            struct sock *ch = sk_get(kids[k]);
            if (ch) ch->listener = -1;
            sock_free(kids[k]);
        }
    }
    sock_unqueue(s);
    memset(s, 0, sizeof(*s));
}

int sock_bind(int idx, ip_t addr, u16 port, u32 uid) {
    struct sock *s = sk_get(idx);
    if (!s || s->state != SK_CLOSED || s->bound) return -1;
    if (port == 0) {
        port = ephem_alloc(s->type);
        if (port == 0) return -1;
    }
    /* Privileged ports are root-only, like Linux. The check
       lives in bind (and is repeated in listen), never in
       the packet path — a non-root listener can never be
       created in the first place. */
    if (port < 1024 && uid != 0) return -2;
    if (!ip_is_zero(addr)) {
        ip_t mine; net_ip_addr(&mine);
        if (!ip_equal(addr, mine)) return -1;
    }
    if (port_in_use(s->type, port, idx)) return -1;
    net_ip_addr(&s->local_ip);
    s->local_port = port;
    s->bound = 1;
    return 0;
}

int sock_listen(int idx, int backlog, u32 uid) {
    struct sock *s = sk_get(idx);
    if (!s || s->type != SK_STREAM) return -1;
    if (s->state != SK_CLOSED) return -1;
    if (!s->bound) {
        if (sock_bind(idx, ip_from_u32(0), 0, uid) != 0) return -1;
        s = sk_get(idx);
        if (!s) return -1;
    }
    if (s->local_port < 1024 && uid != 0) return -2;
    if (backlog < 1) backlog = 1;
    if (backlog > SK_BACKLOG_MAX) backlog = SK_BACKLOG_MAX;
    s->pend_n = 0;
    s->backlog_cap = backlog;
    s->state = SK_LISTEN;
    return 0;
}

int sock_accept(int idx, int *child_out) {
    struct sock *s = sk_get(idx);
    if (!s || s->state != SK_LISTEN) return -1;
    if (s->pend_n <= 0) return -1;
    int c = s->pend[0];
    for (int j = 1; j < s->pend_n; j++) s->pend[j - 1] = s->pend[j];
    s->pend_n--;
    struct sock *ch = sk_get(c);
    if (!ch) return -1;
    ch->listener = -1;
    *child_out = c;
    return 0;
}

int sock_connect(int idx, ip_t dst, u16 port) {
    struct sock *s = sk_get(idx);
    if (!s || port == 0) return -1;
    if (!net_ip_configured()) return -1;
    if (s->type == SK_DGRAM) {
        if (!s->bound) {
            u16 ep = ephem_alloc(SK_DGRAM);
            if (ep == 0) return -1;
            net_ip_addr(&s->local_ip);
            s->local_port = ep;
            s->bound = 1;
        }
        s->remote_ip = dst;
        s->remote_port = port;
        s->udp_connected = 1;
        s->state = SK_ESTABLISHED; /* "connected" UDP */
        return 0;
    }
    if (s->state != SK_CLOSED) return -1;
    if (!s->bound) {
        u16 ep = ephem_alloc(SK_STREAM);
        if (ep == 0) return -1;
        net_ip_addr(&s->local_ip);
        s->local_port = ep;
        s->bound = 1;
    }
    s->remote_ip = dst;
    s->remote_port = port;
    iss_counter++;
    s->iss = (timer_ticks * 0x9E3779B9u) ^ (iss_counter * 0x01000193u) ^ 0x12345678u;
    s->snd_una = s->iss;
    s->snd_nxt = s->iss;
    s->rcv_nxt = 0;
    s->peer_closed = 0;
    dbg_reset();
    s->state = SK_SYN_SENT;
    u32 start = timer_ticks;
    u32 last_syn = 0;
    int sent = 0;
    while (timer_ticks - start < 300) {
        /* Retransmit at most once per 100 ticks (the legacy
           client's SYN-flood fix, kept verbatim). */
        if (!sent || timer_ticks - last_syn >= 100) {
            s->snd_nxt = s->iss;
            if (sock_send_seg(s, 0x02, 0, 0, 1) != 0) { s->state = SK_CLOSED; return -1; }
            sent = 1;
            last_syn = timer_ticks;
        }
        net_poll();
        s = sk_get(idx);
        if (!s) return -1;
        if (s->state == SK_ESTABLISHED) return 0;
        if (s->state == SK_CLOSED) return -1;
    }
    s->state = SK_CLOSED;
    return -1;
}

int sock_tcp_send(int idx, const u8 *data, u32 len) {
    struct sock *s = sk_get(idx);
    if (!s || s->type != SK_STREAM) return -1;
    if (s->state != SK_ESTABLISHED && s->state != SK_CLOSE_WAIT) return -1;
    if (len > SK_MAX_SEG) return -1;
    u32 base = s->snd_nxt;
    if (sock_send_seg(s, 0x18, data, len, 0) != 0) return -1;
    s->snd_nxt = base + len;
    u32 start = timer_ticks;
    int resent = 0;
    while (timer_ticks - start < 200) {
        net_poll();
        s = sk_get(idx);
        if (!s) return -1;
        if (s->snd_una >= s->snd_nxt) return 0;
        if (!resent && timer_ticks - start >= 100) {
            s->snd_nxt = base;
            if (sock_send_seg(s, 0x18, data, len, 0) != 0) return -1;
            s->snd_nxt = base + len;
            resent = 1;
        }
        if (s->state != SK_ESTABLISHED && s->state != SK_CLOSE_WAIT) return -1;
    }
    return -1;
}

static int sock_tcp_drain(struct sock *s, u8 *buf, u32 max, u32 *done_out) {
    if (s->rx.tcp.len > 0) {
        u32 was_full = (s->rx.tcp.len == SK_RX_SIZE);
        u32 n = s->rx.tcp.len < max ? s->rx.tcp.len : max;
        memcpy(buf, s->rx.tcp.buf, n);
        memmove(s->rx.tcp.buf, s->rx.tcp.buf + n, s->rx.tcp.len - n);
        s->rx.tcp.len -= n;
        *done_out = n;
        dbg_drain++;
        if (was_full) dbg_drainfull++;
        /* Window update on EVERY drain that frees space (not
           just full->non-full): with a dynamic window the
           sender's usable window is (last ACK + last
           advertised window), and it does not grow when the
           app drains unless an ACK tells it so. Draining
           without ACKing wedges the connection: the sender
           sits at its old limit with everything ACKed (so no
           retransmit timer fires), while the guest waits for
           data — a silent deadlock until the reader's
           deadline, truncating the download (20 KB slirp
           fetch stalled at 3373 bytes with a 2048-byte
           buffer and at 6861 with 4096, both with 0 gap /
           0 partial drops: the guest was correct, the sender
           was simply never told the window reopened). The
           legacy client never hit this because it advertised
           a CONSTANT 4096 window, which slides forward with
           every ACK on its own. One ACK per drain is the
           same rate as the per-segment ACKs and cannot loop
           (peers do not ACK an ACK). */
        if (s->state == SK_ESTABLISHED) sock_send_ack(s);
        return 1; /* had data */
    }
    return 0;
}

int sock_tcp_recv(int idx, u8 *buf, u32 max, u32 timeout_ticks) {
    struct sock *s = sk_get(idx);
    if (!s || s->type != SK_STREAM) return -1;
    u32 start = timer_ticks;
    while (timer_ticks - start < timeout_ticks) {
        s = sk_get(idx);
        if (!s) return -1;
        u32 done = 0;
        if (sock_tcp_drain(s, buf, max, &done)) return (int)done;
        if (s->state == SK_CLOSED || s->peer_closed) return -1;
        net_poll();
    }
    /* Timeout slice: check once more before giving up, so a
       segment that arrived in the last poll is not missed. */
    s = sk_get(idx);
    if (!s) return -1;
    u32 done = 0;
    if (sock_tcp_drain(s, buf, max, &done)) return (int)done;
    if (s->state == SK_CLOSED || s->peer_closed) return -1;
    return 0;
}

int sock_tcp_recv_nb(int idx, u8 *buf, u32 max, u32 *done_out) {
    struct sock *s = sk_get(idx);
    if (!s || s->type != SK_STREAM) return -1;
    net_poll();
    s = sk_get(idx);
    if (!s) return -1;
    if (sock_tcp_drain(s, buf, max, done_out)) return 0;
    if (s->state == SK_CLOSED || s->peer_closed) return -1;
    *done_out = 0;
    return 0;
}

void sock_close(int idx) {
    struct sock *s = sk_get(idx);
    if (!s) return;
    if (s->type == SK_STREAM) {
        /* FIN|ACK, then a brief drain so the peer's FIN (if
           any) is ACKed before the slot vanishes — the
           legacy client's behaviour, kept. */
        (void)sock_send_seg(s, 0x11, 0, 0, 0);
        s->snd_nxt++;
        u32 start = timer_ticks;
        while (timer_ticks - start < 50) net_poll();
    }
    sock_free(idx);
}

int sock_udp_send(int idx, ip_t dst, u16 dport, const u8 *data, u32 len) {
    struct sock *s = sk_get(idx);
    if (!s || s->type != SK_DGRAM) return -1;
    if (len > 1300) return -1;
    if (!s->bound) {
        u16 ep = ephem_alloc(SK_DGRAM);
        if (ep == 0) return -1;
        net_ip_addr(&s->local_ip);
        s->local_port = ep;
        s->bound = 1;
    }
    return net_udp_send(dst, dport, s->local_port, data, len);
}

int sock_udp_send_connected(int idx, const u8 *data, u32 len) {
    struct sock *s = sk_get(idx);
    if (!s || s->type != SK_DGRAM) return -1;
    if (!s->udp_connected) return -1;
    return sock_udp_send(idx, s->remote_ip, s->remote_port, data, len);
}

int sock_udp_recv(int idx, u8 *buf, u32 max, ip_t *src_out, u16 *sport_out,
                  u32 timeout_ticks) {
    struct sock *s = sk_get(idx);
    if (!s || s->type != SK_DGRAM) return -1;
    u32 start = timer_ticks;
    while (timer_ticks - start < timeout_ticks) {
        s = sk_get(idx);
        if (!s) return -1;
        if (s->rx.udp.len > 0) {
            u32 n = s->rx.udp.len < max ? s->rx.udp.len : max;
            memcpy(buf, s->rx.udp.buf, n);
            if (src_out) *src_out = s->rx.udp.src;
            if (sport_out) *sport_out = s->rx.udp.sport;
            s->rx.udp.len = 0;
            return (int)n;
        }
        net_poll();
    }
    s = sk_get(idx);
    if (!s) return -1;
    if (s->rx.udp.len > 0) {
        u32 n = s->rx.udp.len < max ? s->rx.udp.len : max;
        memcpy(buf, s->rx.udp.buf, n);
        if (src_out) *src_out = s->rx.udp.src;
        if (sport_out) *sport_out = s->rx.udp.sport;
        s->rx.udp.len = 0;
        return (int)n;
    }
    return 0;
}

int sock_udp_recv_nb(int idx, u8 *buf, u32 max, ip_t *src_out, u16 *sport_out,
                     u32 *done_out) {
    struct sock *s = sk_get(idx);
    if (!s || s->type != SK_DGRAM) return -1;
    net_poll();
    s = sk_get(idx);
    if (!s) return -1;
    if (s->rx.udp.len > 0) {
        u32 n = s->rx.udp.len < max ? s->rx.udp.len : max;
        memcpy(buf, s->rx.udp.buf, n);
        if (src_out) *src_out = s->rx.udp.src;
        if (sport_out) *sport_out = s->rx.udp.sport;
        s->rx.udp.len = 0;
        *done_out = n;
        return 0;
    }
    *done_out = 0;
    return 0;
}

/* ---- RX dispatch ---- */

static void sock_handle_seg(struct sock *s, u8 flags, u32 seq, u32 ack,
                            const u8 *data, u32 data_len) {
    if (flags & 0x04) { /* RST */
        if (s->listener >= 0) {
            /* Not yet accepted: vanish from the backlog. */
            sock_unqueue(s);
            sock_free((int)(s - socks));
        } else {
            s->state = SK_CLOSED;
        }
        return;
    }
    if (s->state == SK_SYN_SENT) {
        if ((flags & 0x12) == 0x12 && ack == s->iss + 1) {
            s->rcv_nxt = seq + 1;
            s->snd_una = ack;
            s->snd_nxt = ack;
            s->state = SK_ESTABLISHED;
            sock_send_ack(s);
            /* Data piggybacked on the SYN-ACK is recovered
               by the peer's retransmit (its first data byte
               sits at rcv_nxt, see below); fall through so
               a bare ACK-only segment still lands here. */
        } else {
            return;
        }
    } else if (s->state == SK_SYN_RCVD) {
        if (flags & 0x02) {
            /* Peer retransmitted its SYN: resend SYN-ACK. */
            s->snd_nxt = s->iss;
            (void)sock_send_seg(s, 0x12, 0, 0, 1);
            return;
        }
        if ((flags & 0x10) && ack == s->iss + 1) {
            s->snd_una = ack;
            s->snd_nxt = ack;
            s->state = SK_ESTABLISHED;
            struct sock *l = sk_get(s->listener);
            if (l && l->state == SK_LISTEN) {
                if (l->pend_n < l->backlog_cap) {
                    l->pend[l->pend_n++] = (int)(s - socks);
                } else {
                    /* Backlog full: honest backpressure —
                       reset and free instead of queueing
                       a connection accept() can never see. */
                    (void)sock_send_seg(s, 0x04, 0, 0, 0);
                    sock_unqueue(s);
                    sock_free((int)(s - socks));
                    return;
                }
            } else {
                /* Listener went away mid-handshake. */
                s->listener = -1;
                sock_free((int)(s - socks));
                return;
            }
        } else {
            return;
        }
    }
    if (s->state != SK_ESTABLISHED && s->state != SK_CLOSE_WAIT) return;
    if (ack > s->snd_una && ack <= s->snd_nxt) s->snd_una = ack;
    if (flags & 0x02) {
        /* Stray SYN on an established connection: re-ACK,
           never re-handshake. */
        sock_send_ack(s);
        return;
    }
    if (data_len > 0) {
        /* Retransmit straddling the receive edge: the peer
           resent a segment that starts before rcv_nxt (it
           was partially taken earlier, or it overlaps data
           already buffered). Take only the new tail at
           rcv_nxt instead of dropping the whole segment —
           otherwise a whole-segment retransmit after a
           partial take can never be accepted and the
           connection wedges. Bytes before rcv_nxt are
           already buffered and are never overwritten. */
        if (seq != s->rcv_nxt && seq < s->rcv_nxt &&
            seq + data_len > s->rcv_nxt) {
            u32 skip = s->rcv_nxt - seq;
            data += skip;
            data_len -= skip;
            seq = s->rcv_nxt;
            dbg_straddle++;
        }
        dbg_rxseg++;
        if (seq == s->rcv_nxt) {
            u32 room = SK_RX_SIZE - s->rx.tcp.len;
            u32 take = data_len < room ? data_len : room;
            if (take < data_len) dbg_partial++;
            if (take > 0) {
                memcpy(s->rx.tcp.buf + s->rx.tcp.len, data, take);
                s->rx.tcp.len += take;
                s->rcv_nxt += take;
                dbg_rxtake += take;
            }
            sock_send_ack(s);
        } else {
            dbg_gapdrop++;
            sock_send_ack(s);
        }
    }
    if (flags & 0x01) { /* FIN */
        /* Only a FIN at the exact receive position closes
           the peer side (the legacy client's stale-FIN
           fix, kept: any other FIN is just ACKed). */
        if (seq + data_len == s->rcv_nxt) {
            s->rcv_nxt++;
            sock_send_ack(s);
            s->peer_closed = 1;
            if (s->state == SK_ESTABLISHED) s->state = SK_CLOSE_WAIT;
        } else if (data_len == 0) {
            sock_send_ack(s);
        }
    }
}

void sock_tcp_rx(const u8 *ip, u32 ip_len, ip_t src) {
    u32 ihl = (ip[0] & 0x0F) * 4;
    if (ip_len < ihl + 20) return;
    const u8 *tcp = ip + ihl;
    u32 seg_len = ip_len - ihl;
    u32 doff = (tcp[12] >> 4) * 4;
    if (doff < 20 || seg_len < doff) return;
    if (seg_len > sizeof(sock_vbuf)) return;
    memcpy(sock_vbuf, tcp, seg_len);
    sock_vbuf[16] = 0; sock_vbuf[17] = 0;
    ip_t mine; net_ip_addr(&mine);
    if (tcp_checksum(src, mine, sock_vbuf, seg_len) != sget16(tcp + 16)) return;
    u16 sport = sget16(tcp);
    u16 dport = sget16(tcp + 2);
    u8 flags = tcp[13];
    u32 seq = sget32(tcp + 4);
    u32 ack = sget32(tcp + 8);
    const u8 *data = tcp + doff;
    u32 data_len = seg_len - doff;
    /* Existing connections first (4-tuple match): a
       retransmitted SYN for a half-open child must reach
       that child, never spawn a second one. */
    for (int i = 0; i < SK_MAX; i++) {
        struct sock *s = &socks[i];
        if (!s->used || s->type != SK_STREAM) continue;
        if (s->state == SK_CLOSED || s->state == SK_LISTEN) continue;
        if (s->local_port != dport) continue;
        if (!ip_equal(s->remote_ip, src)) continue;
        if (s->remote_port != sport) continue;
        sock_handle_seg(s, flags, seq, ack, data, data_len);
        return;
    }
    /* New connection: a bare SYN to a listening port spawns
       a child socket in SYN-RCVD. Anything else (data, ACK
       or FIN for no socket) is dropped — there is nobody
       to answer it, and answering with a RST for every stray
       segment would let a scanner enumerate the table. */
    if ((flags & 0x12) == 0x02) {
        for (int i = 0; i < SK_MAX; i++) {
            struct sock *l = &socks[i];
            if (!l->used || l->type != SK_STREAM) continue;
            if (l->state != SK_LISTEN) continue;
            if (l->local_port != dport) continue;
            int c;
            if (sock_alloc(SK_STREAM, &c) != 0) return; /* table full: drop */
            struct sock *ch = &socks[c];
            ch->bound = 1;
            net_ip_addr(&ch->local_ip);
            ch->local_port = dport;
            ch->remote_ip = src;
            ch->remote_port = sport;
            ch->listener = i;
            iss_counter++;
            ch->iss = (timer_ticks * 0x9E3779B9u) ^ (iss_counter * 0x01000193u) ^ 0x12345678u;
            ch->snd_una = ch->iss;
            ch->snd_nxt = ch->iss;
            ch->rcv_nxt = seq + 1;
            ch->state = SK_SYN_RCVD;
            ch->last_syn_tick = timer_ticks;
            dbg_reset();
            (void)sock_send_seg(ch, 0x12, 0, 0, 1);
            return;
        }
    }
}

/* Legacy net.c entry point name, kept so net_rx_frame is
   untouched: tcp_rx IS the socket dispatch now. */
void tcp_rx(const u8 *ip, u32 ip_len, ip_t src) {
    sock_tcp_rx(ip, ip_len, src);
}

int sock_udp_rx_dispatch(const u8 *ip, u32 ip_len, ip_t src) {
    u32 ihl = (ip[0] & 0x0F) * 4;
    if (ip_len < ihl + 8) return 0;
    const u8 *udp = ip + ihl;
    u32 udp_len = sget16(udp + 4);
    if (udp_len < 8 || udp_len > ip_len - ihl) return 0;
    u16 sport = sget16(udp);
    u16 dport = sget16(udp + 2);
    const u8 *data = udp + 8;
    u32 data_len = udp_len - 8;
    for (int i = 0; i < SK_MAX; i++) {
        struct sock *s = &socks[i];
        if (!s->used || s->type != SK_DGRAM) continue;
        if (!s->bound || s->local_port != dport) continue;
        if (s->udp_connected &&
            (!ip_equal(s->remote_ip, src) || s->remote_port != sport))
            continue;
        /* Bound sockets take precedence over the built-in
           DHCP/DNS clients (a program that binds 68 or 53
           owns that port — documented in §15.2 notes). */
        if (s->rx.udp.len > 0) return 1; /* queue full: drop, but consumed */
        if (data_len > SK_RX_SIZE) data_len = SK_RX_SIZE;
        memcpy(s->rx.udp.buf, data, data_len);
        s->rx.udp.len = data_len;
        s->rx.udp.src = src;
        s->rx.udp.sport = sport;
        return 1;
    }
    return 0;
}

void sock_dump(void) {
    /* Implemented with console_printf (kernel side only). */
    extern void console_printf(const char *fmt, ...);
    int any = 0;
    for (int i = 0; i < SK_MAX; i++) {
        struct sock *s = &socks[i];
        if (!s->used) continue;
        any = 1;
        console_printf("sock %d %s %s local %u.%u.%u.%u:%u remote %u.%u.%u.%u:%u pend %d\n",
                       i, s->type == SK_STREAM ? "stream" : "dgram",
                       sk_state_name(s->state),
                       s->local_ip.b[0], s->local_ip.b[1], s->local_ip.b[2], s->local_ip.b[3],
                       s->local_port,
                       s->remote_ip.b[0], s->remote_ip.b[1], s->remote_ip.b[2], s->remote_ip.b[3],
                       s->remote_port,
                       s->state == SK_LISTEN ? s->pend_n : 0);
    }
    if (!any) console_printf("sock: no sockets\n");
}

int sock_state(int idx) {
    struct sock *s = sk_get(idx);
    return s ? s->state : -1;
}

int sock_type(int idx) {
    struct sock *s = sk_get(idx);
    return s ? s->type : -1;
}

u16 sock_local_port(int idx) {
    struct sock *s = sk_get(idx);
    return s ? s->local_port : 0;
}

int sock_pending_count(int idx) {
    struct sock *s = sk_get(idx);
    if (!s || s->state != SK_LISTEN) return -1;
    return s->pend_n;
}
