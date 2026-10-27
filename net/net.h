#ifndef NXTS_NET_H
#define NXTS_NET_H
#include "../kernel/common.h"

/* nxtsOS networking (Phase 9). Design notes, kept short because
   the details matter for anyone auditing this code:
   - The driver is POLLED, not interrupt-driven (same robustness
     reasoning as the v0.7.2 keyboard poll: a lost IRQ must not
     wedge the stack). net_poll() is called by shell commands
     that wait for network replies, and by nettest.
   - All receive parsing is bounds-checked against the actual
     frame length. A packet that claims a longer length than
     the frame carries is dropped, never read past the buffer.
   - No packet is ever executed or trusted: payloads are data.
   - DHCP/DNS/TCP state lives in this module only; user programs
     do not get raw sockets in v0.9.0 (shell commands only).
     A user-mode socket API is a later phase, not a hidden
     half-finished one. */

/* Ethernet / IP addresses. IP is stored as 4 bytes in network
   order (a.b.c.d -> {a,b,c,d}); helpers convert to/from u32. */
typedef struct { u8 b[6]; } mac_t;
typedef struct { u8 b[4]; } ip_t;
static inline u32 ip_to_u32(ip_t ip) {
    return ((u32)ip.b[0] << 24) | ((u32)ip.b[1] << 16) |
           ((u32)ip.b[2] << 8) | (u32)ip.b[3];
}
static inline ip_t ip_from_u32(u32 v) {
    ip_t ip; ip.b[0] = (u8)(v >> 24); ip.b[1] = (u8)(v >> 16);
    ip.b[2] = (u8)(v >> 8); ip.b[3] = (u8)v; return ip;
}
static inline int ip_equal(ip_t a, ip_t b) { return memcmp(a.b, b.b, 4) == 0; }
static inline int ip_is_zero(ip_t a) { return a.b[0]==0 && a.b[1]==0 && a.b[2]==0 && a.b[3]==0; }

/* Driver (net/e1000.c). */
int  net_init(void);            /* 0 ok (NIC found), -1 no NIC */
int  net_present(void);
void net_mac(mac_t *out);
int  net_send(const u8 *frame, u32 len); /* Ethernet frame, len <= 1518 */
void net_poll(void);            /* process received frames, non-blocking */
u32  net_rx_count(void);
u32  net_tx_count(void);
u32  net_drop_count(void);
void net_dbg(void);

u16 net_checksum(const u8 *data, u32 len);

/* Stack (net/net.c). Called by net_poll's receive path. */
void net_rx_frame(const u8 *frame, u32 len); /* test injection entry too */
int  net_arp_resolve(ip_t ip, mac_t *out);   /* cached or request+wait */
int  net_ip_configured(void);
void net_ip_addr(ip_t *out);
void net_ip_gateway(ip_t *out);
void net_ip_dns(ip_t *out);
void net_ip_netmask(ip_t *out);
/* Send an IPv4 packet (payload already includes its own header
   space? No: payload is the L4 segment, proto = 1 ICMP, 6 TCP,
   17 UDP). The stack fills IP header + checksum + Ethernet. */
int  net_ip_send(ip_t dst, u8 proto, const u8 *payload, u32 payload_len);
int  net_udp_send(ip_t dst, u16 dport, u16 sport, const u8 *payload, u32 len);

int net_parse_ip(const char *s, ip_t *out); /* dotted quad -> ip, 1 ok */
void net_set_dns(ip_t ip); /* diagnostic DNS override */

/* DHCP (net/net.c). Blocks (polling) up to ~10 s. */
int  net_dhcp(void);             /* 0 configured, -1 failed */

/* ICMP ping (net/net.c). Blocks up to ~3 s. */
int  net_ping(ip_t dst);         /* 0 reply received, -1 timeout/fail */

/* DNS (net/net.c). Blocks up to ~3 s per server attempt. */
int  net_dns_lookup(const char *name, ip_t *out); /* 0 found */

/* TCP client (net/tcp.c). One connection at a time (v0.9.0
   scope: a client for HTTP/HTTPS, not a general socket layer). */
int  net_tcp_connect(ip_t dst, u16 port);       /* 0 connected */
int  net_tcp_send(const u8 *data, u32 len);     /* 0 sent */
int  net_tcp_recv(u8 *buf, u32 max, u32 timeout_ticks); /* bytes, 0 = timeout/closed */
void net_tcp_close(void);
int  net_tcp_connected(void);

/* HTTP (net/net.c, over net_tcp_*). Response body is copied to
   buf (up to max-1 bytes, NUL-terminated); returns body length
   or -1. Host may be a name (DNS) or dotted IP. v0.10.0: a body
   longer than the buffer is truncated (prefix kept, rest drained)
   and net_fetch_truncated() reports it, instead of failing. */
int  net_http_get(const char *host, u16 port, const char *path, char *buf, u32 max);
int  net_fetch_truncated(void);
void net_set_fetch_truncated(int v);

/* TLS 1.2 client (net/tls.c). Returns body length or -1; on
   certificate failure returns -2 (refused, never "accept"). */
int  net_https_get(const char *host, u16 port, const char *path, char *buf, u32 max);

/* Adversarial test entry (net/nettest.c). */
int  net_test_run(void);         /* 0 all checks pass */

#endif
