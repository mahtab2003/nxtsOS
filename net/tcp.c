/* Minimal TCP client (Phase 9.1): one connection at a time,
   for HTTP/HTTPS. In-order data only; out-of-order segments
   are dropped and re-ACKed (the peer retransmits). No window
   scaling, no SACK, no congestion control — this is a client
   for short local/LAN requests, not a general socket layer.
   Known limits, stated plainly: initial sequence numbers are
   derived from the timer (predictable — not safe against a
   hostile on-path attacker in production); retransmission is
   a single fixed timer, not exponential backoff. */
#include "net.h"
#include "../drivers/pit.h"

static void tput16(u8 *p, u16 v) { p[0] = (u8)(v >> 8); p[1] = (u8)v; }
static void tput32(u8 *p, u32 v) {
    p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16); p[2] = (u8)(v >> 8); p[3] = (u8)v;
}
static u16 tget16(const u8 *p) { return (u16)(((u16)p[0] << 8) | p[1]); }
static u32 tget32(const u8 *p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

#define TCP_CLOSED 0
#define TCP_SYN_SENT 1
#define TCP_ESTABLISHED 2
#define TCP_FIN_SENT 3

static int tcp_state = TCP_CLOSED;
static ip_t tcp_peer;
static u16 tcp_peer_port = 0, tcp_local_port = 0;
static u32 tcp_iss = 0, tcp_snd_una = 0, tcp_snd_nxt = 0, tcp_rcv_nxt = 0;
static int tcp_peer_closed = 0;
static u8 tcp_rxbuf[4096];
static u32 tcp_rx_len = 0;

int net_tcp_connected(void) { return tcp_state == TCP_ESTABLISHED; }

static u16 tcp_checksum(ip_t src, ip_t dst, const u8 *seg, u32 seg_len) {
    /* Pseudo-header + segment, checksum field included must
       fold to 0xFFFF on verification. */
    u8 pseudo[12];
    memcpy(pseudo, src.b, 4);
    memcpy(pseudo + 4, dst.b, 4);
    pseudo[8] = 0; pseudo[9] = 6;
    tput16(pseudo + 10, (u16)seg_len);
    u32 sum = 0;
    for (u32 i = 0; i + 1 < 12; i += 2) sum += ((u32)pseudo[i] << 8) | pseudo[i + 1];
    for (u32 i = 0; i + 1 < seg_len; i += 2) sum += ((u32)seg[i] << 8) | seg[i + 1];
    if (seg_len & 1) sum += (u32)seg[seg_len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (u16)(~sum & 0xFFFF);
}

static int tcp_send_seg(u8 flags, const u8 *data, u32 len, int with_mss) {
    u8 seg[1500];
    if (20 + (with_mss ? 4 : 0) + len > sizeof(seg)) return -1;
    ip_t mine; net_ip_addr(&mine);
    tput16(seg, tcp_local_port);
    tput16(seg + 2, tcp_peer_port);
    tput32(seg + 4, tcp_snd_nxt);
    tput32(seg + 8, tcp_rcv_nxt);
    u32 hlen = 20 + (with_mss ? 4 : 0);
    seg[12] = (u8)((hlen / 4) << 4);
    seg[13] = flags;
    tput16(seg + 14, 4096); /* window */
    tput16(seg + 16, 0);
    tput16(seg + 18, 0);
    if (with_mss) {
        seg[20] = 2; seg[21] = 4; tput16(seg + 22, 1460);
    }
    memcpy(seg + hlen, data, len);
    tput16(seg + 16, tcp_checksum(mine, tcp_peer, seg, hlen + len));
    return net_ip_send(tcp_peer, 6, seg, hlen + len);
}

int net_tcp_connect(ip_t dst, u16 port) {
    if (!net_ip_configured()) return -1;
    tcp_peer = dst; tcp_peer_port = port;
    tcp_local_port = (u16)(49152 + (timer_ticks % 10000));
    tcp_iss = (timer_ticks * 0x9E3779B9u) ^ 0x12345678u;
    tcp_snd_una = tcp_iss; tcp_snd_nxt = tcp_iss;
    tcp_rcv_nxt = 0; tcp_rx_len = 0; tcp_peer_closed = 0;
    tcp_state = TCP_SYN_SENT;
    u32 start = timer_ticks;
    u32 last_syn = 0;
    int sent = 0;
    while (timer_ticks - start < 300) {
        /* Retransmit at most once per 100 ticks. (An earlier
           version tested (elapsed % 100 == 0), which is true
           for every poll iteration inside one tick and flooded
           the peer with SYNs — caught by the peer test.) */
        if (!sent || timer_ticks - last_syn >= 100) {
            /* SYN with MSS option; snd_nxt stays at iss until
               the SYN is ACKed (SYN consumes one seq number). */
            tcp_snd_nxt = tcp_iss;
            if (tcp_send_seg(0x02, 0, 0, 1) != 0) { tcp_state = TCP_CLOSED; return -1; }
            sent = 1;
            last_syn = timer_ticks;
        }
        net_poll();
        if (tcp_state == TCP_ESTABLISHED) return 0;
        if (tcp_state == TCP_CLOSED) return -1;
    }
    tcp_state = TCP_CLOSED;
    return -1;
}

int net_tcp_send(const u8 *data, u32 len) {
    if (tcp_state != TCP_ESTABLISHED) return -1;
    if (len > 1400) return -1;
    u32 base = tcp_snd_nxt;
    if (tcp_send_seg(0x18, data, len, 0) != 0) return -1;
    tcp_snd_nxt = base + len;
    /* Wait for the ACK (a data segment from the peer also
       carries it). Retransmit once at 100 ticks. */
    u32 start = timer_ticks;
    int resent = 0;
    while (timer_ticks - start < 200) {
        net_poll();
        if (tcp_snd_una >= tcp_snd_nxt) return 0;
        if (!resent && timer_ticks - start >= 100) {
            tcp_snd_nxt = base;
            if (tcp_send_seg(0x18, data, len, 0) != 0) return -1;
            tcp_snd_nxt = base + len;
            resent = 1;
        }
        if (tcp_state != TCP_ESTABLISHED) return -1;
    }
    return -1;
}

int net_tcp_recv(u8 *buf, u32 max, u32 timeout_ticks) {
    u32 start = timer_ticks;
    while (timer_ticks - start < timeout_ticks) {
        if (tcp_rx_len > 0) {
            u32 n = tcp_rx_len < max ? tcp_rx_len : max;
            memcpy(buf, tcp_rxbuf, n);
            memmove(tcp_rxbuf, tcp_rxbuf + n, tcp_rx_len - n);
            tcp_rx_len -= n;
            return (int)n;
        }
        if (tcp_state == TCP_CLOSED || tcp_peer_closed) {
            if (tcp_rx_len == 0) return -1;
        }
        net_poll();
    }
    return 0; /* timeout slice, connection still open */
}

void net_tcp_close(void) {
    if (tcp_state == TCP_ESTABLISHED) {
        tcp_send_seg(0x11, 0, 0, 0); /* FIN|ACK */
        tcp_snd_nxt++;
        tcp_state = TCP_FIN_SENT;
        u32 start = timer_ticks;
        while (timer_ticks - start < 50) net_poll();
    }
    tcp_state = TCP_CLOSED;
}

void tcp_rx(const u8 *ip, u32 ip_len, ip_t src) {
    u32 ihl = (ip[0] & 0x0F) * 4;
    if (ip_len < ihl + 20) return;
    const u8 *tcp = ip + ihl;
    u32 seg_len = ip_len - ihl;
    u32 doff = (tcp[12] >> 4) * 4;
    if (doff < 20 || seg_len < doff) return;
    /* Verify checksum: recompute over pseudo-header + segment
       with the checksum field zeroed, and compare with the
       received checksum. tcp_checksum() returns the value to
       insert, so this zero-and-compare form is the check. */
    {
        /* Recompute: sum pseudo + segment with field zeroed. */
        u8 tmp[1500];
        if (seg_len > sizeof(tmp)) return;
        memcpy(tmp, tcp, seg_len);
        tmp[16] = 0; tmp[17] = 0;
        ip_t mine; net_ip_addr(&mine);
        if (tcp_checksum(src, mine, tmp, seg_len) != tget16(tcp + 16)) return;
    }
    if (!ip_equal(src, tcp_peer)) return;
    if (tget16(tcp) != tcp_peer_port) return;
    /* Destination port MUST match our local port: without this,
       a delayed segment from a previous connection (same server
       ip/port, e.g. its FIN arriving after we closed and
       reconnected) was accepted into the new connection and
       could truncate a download mid-stream. This was the
       intermittent repo-fetch hash-mismatch flake. */
    if (tget16(tcp + 2) != tcp_local_port) return;
    if (tcp_state == TCP_CLOSED) return;
    u8 flags = tcp[13];
    u32 seq = tget32(tcp + 4);
    u32 ack = tget32(tcp + 8);
    if (flags & 0x04) { /* RST */
        tcp_state = TCP_CLOSED;
        return;
    }
    if (tcp_state == TCP_SYN_SENT) {
        if ((flags & 0x12) == 0x12 && ack == tcp_iss + 1) {
            tcp_rcv_nxt = seq + 1;
            tcp_snd_una = ack;
            tcp_snd_nxt = ack;
            tcp_state = TCP_ESTABLISHED;
            /* ACK the SYN-ACK. */
            tcp_send_seg(0x10, 0, 0, 0);
            /* Data may already be piggybacked in this segment:
               fall through to data handling below. */
        } else {
            return;
        }
    }
    if (tcp_state != TCP_ESTABLISHED && tcp_state != TCP_FIN_SENT) return;
    /* ACK progress (only forward, never backwards). */
    if (ack > tcp_snd_una && ack <= tcp_snd_nxt) tcp_snd_una = ack;
    const u8 *data = tcp + doff;
    u32 data_len = seg_len - doff;
    if (data_len > 0) {
        if (seq == tcp_rcv_nxt) {
            u32 room = sizeof(tcp_rxbuf) - tcp_rx_len;
            u32 take = data_len < room ? data_len : room;
            if (take > 0) {
                memcpy(tcp_rxbuf + tcp_rx_len, data, take);
                tcp_rx_len += take;
                tcp_rcv_nxt += take;
            }
            /* ACK (even if we took only part: rcv_nxt moved). */
            tcp_send_seg(0x10, 0, 0, 0);
        } else {
            /* Retransmit or gap: re-ACK current rcv_nxt. */
            tcp_send_seg(0x10, 0, 0, 0);
        }
    }
    if (flags & 0x01) { /* FIN */
        /* Only a FIN at the exact receive position closes the
           peer side. The old `|| data_len == 0` accepted ANY
           bare FIN regardless of sequence number, so a stale
           FIN from a previous connection could set
           peer_closed mid-download and truncate it. */
        if (seq + data_len == tcp_rcv_nxt) {
            tcp_rcv_nxt++;
            tcp_send_seg(0x10, 0, 0, 0);
            tcp_peer_closed = 1;
            if (tcp_state == TCP_FIN_SENT) tcp_state = TCP_CLOSED;
        }
    }
    if ((flags & 0x10) && tcp_state == TCP_FIN_SENT && ack >= tcp_snd_nxt) {
        /* Peer ACKed our FIN; wait for its FIN in recv loop. */
    }
}
