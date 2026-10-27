/* nxtsOS network stack core (Phase 9.1): Ethernet, ARP, IPv4,
   ICMP, UDP, DHCP, DNS, HTTP-over-TCP (TCP itself is in
   net/tcp.c). Every receive path is bounds-checked against
   the actual frame length first; a field that claims more
   than the frame carries causes a drop, never an over-read.
   Counters: net_drop_count in e1000.c counts driver-level
   drops; stack drops are counted here in stack_drops. */
#include "net.h"
#include "../drivers/pit.h"

static ip_t our_ip, netmask_ip, gateway_ip, dns_ip;
static int configured = 0;
/* Set by net_http_get/net_https_get when the body was longer than
   the buffer (stored prefix kept, rest drained). Read it right
   after the get call; the next get call resets it. */
static int fetch_truncated = 0;
int net_fetch_truncated(void) { return fetch_truncated; }
void net_set_fetch_truncated(int v) { fetch_truncated = v; }
static u16 ip_id_counter = 0;
static u32 stack_drops = 0;

/* ARP cache: 8 entries, 300 s expiry (30000 ticks at 100 Hz). */
struct arp_entry { ip_t ip; mac_t mac; u32 expiry; int used; };
static struct arp_entry arp_cache[8];

static int mac_is_broadcast(const u8 *m) {
    for (int i = 0; i < 6; i++) if (m[i] != 0xFF) return 0;
    return 1;
}
static int mac_equal(const u8 *a, const u8 *b) { return memcmp(a, b, 6) == 0; }

u16 net_checksum(const u8 *data, u32 len) { /* exported for TCP */
    u32 sum = 0;
    u32 i = 0;
    while (i + 1 < len) {
        sum += ((u32)data[i] << 8) | data[i + 1];
        i += 2;
    }
    if (i < len) sum += (u32)data[i] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (u16)(~sum & 0xFFFF);
}
static void put16(u8 *p, u16 v) { p[0] = (u8)(v >> 8); p[1] = (u8)v; }
static void put32(u8 *p, u32 v) {
    p[0] = (u8)(v >> 24); p[1] = (u8)(v >> 16); p[2] = (u8)(v >> 8); p[3] = (u8)v;
}
static u16 get16(const u8 *p) { return (u16)(((u16)p[0] << 8) | p[1]); }
static u32 get32(const u8 *p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

int net_ip_configured(void) { return configured; }
/* Diagnostic override (shell `dnsset`): point the resolver at a
   chosen server, e.g. the QEMU host at 10.0.2.2. Test-only. */
void net_set_dns(ip_t ip) { dns_ip = ip; }
void net_ip_addr(ip_t *out) { *out = our_ip; }
void net_ip_gateway(ip_t *out) { *out = gateway_ip; }
void net_ip_dns(ip_t *out) { *out = dns_ip; }
void net_ip_netmask(ip_t *out) { *out = netmask_ip; }

/* Raw Ethernet send (caller supplies the full payload after
   the 14-byte header). */
static int eth_send(const u8 *dst_mac, u16 ethertype, const u8 *payload, u32 len) {
    if (len > 1500) return -1;
    u8 frame[1514];
    mac_t mine; net_mac(&mine);
    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, mine.b, 6);
    put16(frame + 12, ethertype);
    memcpy(frame + 14, payload, len);
    return net_send(frame, 14 + len);
}

static void arp_cache_put(ip_t ip, const u8 *mac) {
    int slot = -1;
    for (int i = 0; i < 8; i++) {
        if (arp_cache[i].used && ip_equal(arp_cache[i].ip, ip)) { slot = i; break; }
        if (!arp_cache[i].used && slot < 0) slot = i;
    }
    if (slot < 0) slot = 0; /* evict oldest slot (simple, bounded) */
    arp_cache[slot].ip = ip;
    memcpy(arp_cache[slot].mac.b, mac, 6);
    arp_cache[slot].expiry = timer_ticks + 30000;
    arp_cache[slot].used = 1;
}
static int arp_cache_get(ip_t ip, mac_t *out) {
    for (int i = 0; i < 8; i++) {
        if (arp_cache[i].used && ip_equal(arp_cache[i].ip, ip)) {
            if (timer_ticks > arp_cache[i].expiry) { arp_cache[i].used = 0; return 0; }
            *out = arp_cache[i].mac;
            return 1;
        }
    }
    return 0;
}

int net_arp_resolve(ip_t ip, mac_t *out) {
    if (arp_cache_get(ip, out)) return 0;
    /* ARP request, broadcast. */
    u8 pkt[28];
    put16(pkt, 1); put16(pkt + 2, 0x0800);
    pkt[4] = 6; pkt[5] = 4; put16(pkt + 6, 1);
    mac_t mine; net_mac(&mine);
    memcpy(pkt + 8, mine.b, 6);
    memcpy(pkt + 14, our_ip.b, 4);
    memset(pkt + 18, 0, 6);
    memcpy(pkt + 24, ip.b, 4);
    u8 bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    if (eth_send(bcast, 0x0806, pkt, 28) != 0) return -1;
    u32 start = timer_ticks;
    while (timer_ticks - start < 100) {
        net_poll();
        if (arp_cache_get(ip, out)) return 0;
    }
    return -1;
}

/* IPv4 send: payload is the L4 segment. Routing: same subnet
   (by netmask, when configured) -> direct ARP; otherwise via
   the gateway (when configured); unconfigured (DHCP) callers
   use broadcast or the eth layer directly, not this. */
int net_ip_send(ip_t dst, u8 proto, const u8 *payload, u32 payload_len) {
    if (payload_len > 1400) return -1;
    mac_t dst_mac;
    int is_bcast = (dst.b[0]==255 && dst.b[1]==255 && dst.b[2]==255 && dst.b[3]==255);
    ip_t next_hop = dst;
    if (!is_bcast) {
        if (configured && !ip_is_zero(gateway_ip)) {
            /* Same subnet? (dst & mask) == (our & mask). */
            int same = 1;
            for (int i = 0; i < 4; i++)
                if ((dst.b[i] & netmask_ip.b[i]) != (our_ip.b[i] & netmask_ip.b[i])) same = 0;
            if (!same) next_hop = gateway_ip;
        }
        if (net_arp_resolve(next_hop, &dst_mac) != 0) return -1;
    } else {
        memset(dst_mac.b, 0xFF, 6);
    }
    u8 pkt[1420];
    pkt[0] = 0x45; pkt[1] = 0;
    put16(pkt + 2, (u16)(20 + payload_len));
    put16(pkt + 4, ip_id_counter++);
    put16(pkt + 6, 0); /* no fragmentation */
    pkt[8] = 64; pkt[9] = proto;
    put16(pkt + 10, 0);
    memcpy(pkt + 12, our_ip.b, 4);
    memcpy(pkt + 16, dst.b, 4);
    put16(pkt + 10, net_checksum(pkt, 20));
    memcpy(pkt + 20, payload, payload_len);
    return eth_send(dst_mac.b, 0x0800, pkt, 20 + payload_len);
}

int net_udp_send(ip_t dst, u16 dport, u16 sport, const u8 *payload, u32 len) {
    if (len > 1300) return -1;
    u8 seg[1320];
    put16(seg, sport); put16(seg + 2, dport);
    put16(seg + 4, (u16)(8 + len));
    put16(seg + 6, 0); /* UDP checksum optional, 0 = none */
    memcpy(seg + 8, payload, len);
    return net_ip_send(dst, 17, seg, 8 + len);
}

/* ---- ICMP ---- */
static int ping_wait_id = 0, ping_wait_seq = 0, ping_got = 0;
static void icmp_rx(const u8 *ip, u32 ip_len, ip_t src) {
    /* ip points at the IP header; ip_len is the IP packet length. */
    u32 ihl = (ip[0] & 0x0F) * 4;
    if (ip_len < ihl + 8) { stack_drops++; return; }
    const u8 *icmp = ip + ihl;
    u32 icmp_len = ip_len - ihl;
    if (icmp[0] == 8) {
        /* Echo request to us: reply with same id/seq/payload. */
        u8 reply[1400];
        if (icmp_len > sizeof(reply)) { stack_drops++; return; }
        reply[0] = 0; reply[1] = 0;
        put16(reply + 2, 0);
        memcpy(reply + 4, icmp + 4, icmp_len - 4);
        put16(reply + 2, net_checksum(reply, icmp_len));
        net_ip_send(src, 1, reply, icmp_len);
    } else if (icmp[0] == 0) {
        int id = get16(icmp + 4), seq = get16(icmp + 6);
        if (id == ping_wait_id && seq == ping_wait_seq) ping_got = 1;
    }
}
int net_ping(ip_t dst) {
    u8 req[64];
    ping_wait_id = 0x4E54; /* "NT" */
    ping_wait_seq = (int)(timer_ticks & 0xFFFF);
    ping_got = 0;
    req[0] = 8; req[1] = 0; put16(req + 2, 0);
    put16(req + 4, (u16)ping_wait_id);
    put16(req + 6, (u16)ping_wait_seq);
    for (int i = 8; i < 64; i++) req[i] = (u8)i;
    put16(req + 2, net_checksum(req, 64));
    if (net_ip_send(dst, 1, req, 64) != 0) return -1;
    u32 start = timer_ticks;
    while (timer_ticks - start < 300) {
        net_poll();
        if (ping_got) return 0;
    }
    return -1;
}

/* ---- ARP receive ---- */
static void arp_rx(const u8 *pkt, u32 len) {
    if (len < 28) { stack_drops++; return; }
    if (get16(pkt) != 1 || get16(pkt + 2) != 0x0800) return;
    if (pkt[4] != 6 || pkt[5] != 4) return;
    u16 op = get16(pkt + 6);
    ip_t sender_ip, target_ip;
    memcpy(sender_ip.b, pkt + 14, 4);
    memcpy(target_ip.b, pkt + 24, 4);
    if (op == 2) {
        arp_cache_put(sender_ip, pkt + 8);
        return;
    }
    if (op != 1) return;
    /* Request for us? Reply. */
    if (!configured || !ip_equal(target_ip, our_ip)) return;
    u8 reply[28];
    put16(reply, 1); put16(reply + 2, 0x0800);
    reply[4] = 6; reply[5] = 4; put16(reply + 6, 2);
    mac_t mine; net_mac(&mine);
    memcpy(reply + 8, mine.b, 6);
    memcpy(reply + 14, our_ip.b, 4);
    memcpy(reply + 18, pkt + 8, 6);
    memcpy(reply + 24, sender_ip.b, 4);
    eth_send(pkt + 8, 0x0806, reply, 28);
}

/* Forward declarations for UDP dispatch targets (defined below). */
static void dhcp_rx(const u8 *data, u32 len);
static void dns_rx(const u8 *data, u32 len);
void tcp_rx(const u8 *ip, u32 ip_len, ip_t src);

static void udp_rx(const u8 *ip, u32 ip_len, ip_t src) {
    (void)src;
    u32 ihl = (ip[0] & 0x0F) * 4;
    if (ip_len < ihl + 8) { stack_drops++; return; }
    const u8 *udp = ip + ihl;
    u32 udp_len = get16(udp + 4);
    if (udp_len < 8 || udp_len > ip_len - ihl) { stack_drops++; return; }
    u16 dport = get16(udp + 2);
    const u8 *data = udp + 8;
    u32 data_len = udp_len - 8;
    if (dport == 68) dhcp_rx(data, data_len);
    /* DNS replies arrive at the client's source port (5353,
       fixed in net_dns_lookup), NOT at port 53 — dispatching
       only on 53 dropped every reply. dns_rx itself validates
       the transaction id, so stray packets to 5353 are ignored
       there, not here. (This was the DNS failure in the peer
       test: the reply was sent and arrived, then dropped.) */
    else if (dport == 53 || dport == 5353) dns_rx(data, data_len);
    else stack_drops++; /* no listener */
}

void net_rx_frame(const u8 *frame, u32 len) {
    if (len < 14) { stack_drops++; return; }
    mac_t mine; net_mac(&mine);
    if (!mac_is_broadcast(frame) && !mac_equal(frame, mine.b)) { stack_drops++; return; }
    u16 ethertype = get16(frame + 12);
    const u8 *payload = frame + 14;
    u32 plen = len - 14;
    if (ethertype == 0x0806) { arp_rx(payload, plen); return; }
    if (ethertype != 0x0800) { stack_drops++; return; }
    /* IPv4. */
    if (plen < 20) { stack_drops++; return; }
    if ((payload[0] >> 4) != 4) { stack_drops++; return; }
    u32 ihl = (payload[0] & 0x0F) * 4;
    if (ihl < 20 || plen < ihl) { stack_drops++; return; }
    u32 total = get16(payload + 2);
    if (total < ihl || total > plen) { stack_drops++; return; }
    /* Header checksum: sum over the header including the
       checksum field must fold to 0xFFFF. */
    if (net_checksum(payload, ihl) != 0) { stack_drops++; return; }
    /* Fragmentation: not reassembled in v0.9.0. */
    u16 frag = get16(payload + 6);
    if ((frag & 0x1FFF) != 0 || (frag & 0x2000) != 0) { stack_drops++; return; }
    ip_t src, dst;
    memcpy(src.b, payload + 12, 4);
    memcpy(dst.b, payload + 16, 4);
    /* Accept packets to us, to broadcast, or (before DHCP)
       to 0.0.0.0/255.255.255.255. */
    if (configured) {
        if (!ip_equal(dst, our_ip) &&
            !(dst.b[0]==255 && dst.b[1]==255 && dst.b[2]==255 && dst.b[3]==255)) {
            stack_drops++; return;
        }
    }
    u8 proto = payload[9];
    if (proto == 1) icmp_rx(payload, total, src);
    else if (proto == 17) udp_rx(payload, total, src);
    else if (proto == 6) tcp_rx(payload, total, src);
    else stack_drops++;
}
u32 net_stack_drops(void) { return stack_drops; }

/* ---- DHCP ---- */
static u32 dhcp_xid = 0;
static int dhcp_stage = 0; /* 0 idle, 1 want offer, 2 want ack */
static ip_t dhcp_offered, dhcp_server;
static ip_t dhcp_opt_mask, dhcp_opt_router, dhcp_opt_dns;
static int dhcp_got_offer = 0, dhcp_got_ack = 0;

static void dhcp_parse_options(const u8 *opt, u32 len, int is_ack) {
    u32 pos = 0;
    while (pos < len) {
        u8 code = opt[pos];
        if (code == 255) break;
        if (code == 0) { pos++; continue; }
        if (pos + 1 >= len) break;
        u8 olen = opt[pos + 1];
        if (pos + 2 + olen > len) break;
        const u8 *v = opt + pos + 2;
        if (code == 54 && olen == 4) memcpy(dhcp_server.b, v, 4);
        else if (code == 1 && olen == 4) memcpy(dhcp_opt_mask.b, v, 4);
        else if (code == 3 && olen >= 4) memcpy(dhcp_opt_router.b, v, 4);
        else if (code == 6 && olen >= 4) memcpy(dhcp_opt_dns.b, v, 4);
        (void)is_ack;
        pos += 2 + olen;
    }
}
static void dhcp_rx(const u8 *data, u32 len) {
    if (len < 240) { stack_drops++; return; }
    if (data[0] != 2) return; /* BOOTREPLY only */
    if (get32(data + 4) != dhcp_xid) return;
    mac_t mine; net_mac(&mine);
    if (memcmp(data + 28, mine.b, 6) != 0) return;
    if (get32(data + 236) != 0x63825363u) return; /* magic cookie */
    /* Message type option (53) is the first option in practice,
       but parse the whole option area properly. */
    u8 mtype = 0;
    const u8 *opt = data + 240;
    u32 olen = len - 240, pos = 0;
    while (pos < olen) {
        u8 code = opt[pos];
        if (code == 255) break;
        if (code == 0) { pos++; continue; }
        if (pos + 1 >= olen) break;
        u8 l = opt[pos + 1];
        if (pos + 2 + l > olen) break;
        if (code == 53 && l == 1) mtype = opt[pos + 2];
        pos += 2 + l;
    }
    if (dhcp_stage == 1 && mtype == 2) {
        memcpy(dhcp_offered.b, data + 16, 4); /* yiaddr */
        dhcp_parse_options(opt, olen, 0);
        dhcp_got_offer = 1;
    } else if (dhcp_stage == 2 && mtype == 5) {
        memcpy(dhcp_offered.b, data + 16, 4);
        dhcp_parse_options(opt, olen, 1);
        dhcp_got_ack = 1;
    } else if (dhcp_stage == 2 && mtype == 6) {
        /* NAK: stay failed; the wait loop times out. */
    }
}
static int dhcp_send_msg(u8 mtype, ip_t req_ip, ip_t srv_ip) {
    u8 pkt[512];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 1; pkt[1] = 1; pkt[2] = 6; pkt[3] = 0;
    put32(pkt + 4, dhcp_xid);
    put16(pkt + 8, 0);
    put16(pkt + 10, 0x8000); /* broadcast flag */
    mac_t mine; net_mac(&mine);
    memcpy(pkt + 28, mine.b, 6);
    put32(pkt + 236, 0x63825363u);
    u32 pos = 240;
    pkt[pos++] = 53; pkt[pos++] = 1; pkt[pos++] = mtype;
    if (mtype == 3) {
        pkt[pos++] = 50; pkt[pos++] = 4; memcpy(pkt + pos, req_ip.b, 4); pos += 4;
        pkt[pos++] = 54; pkt[pos++] = 4; memcpy(pkt + pos, srv_ip.b, 4); pos += 4;
    }
    pkt[pos++] = 55; pkt[pos++] = 4;
    pkt[pos++] = 1; pkt[pos++] = 3; pkt[pos++] = 6; pkt[pos++] = 51;
    pkt[pos++] = 255;
    ip_t bcast; bcast.b[0]=255; bcast.b[1]=255; bcast.b[2]=255; bcast.b[3]=255;
    return net_udp_send(bcast, 67, 68, pkt, pos);
}
int net_dhcp(void) {
    if (!net_present()) return -1;
    for (int round = 0; round < 2 && !configured; round++) {
        dhcp_xid = (timer_ticks << 16) ^ 0x4E540000u ^ (u32)(round + 1) * 0x9E3779B9u;
        dhcp_stage = 1; dhcp_got_offer = 0; dhcp_got_ack = 0;
        memset(dhcp_opt_mask.b, 0, 4);
        memset(dhcp_opt_router.b, 0, 4);
        memset(dhcp_opt_dns.b, 0, 4);
        ip_t zero; memset(zero.b, 0, 4);
        if (dhcp_send_msg(1, zero, zero) != 0) return -1;
        u32 start = timer_ticks;
        while (timer_ticks - start < 300 && !dhcp_got_offer) net_poll();
        if (!dhcp_got_offer) continue;
        dhcp_stage = 2;
        if (dhcp_send_msg(3, dhcp_offered, dhcp_server) != 0) return -1;
        start = timer_ticks;
        while (timer_ticks - start < 300 && !dhcp_got_ack) net_poll();
        if (!dhcp_got_ack) continue;
        our_ip = dhcp_offered;
        netmask_ip = ip_is_zero(dhcp_opt_mask) ? ip_from_u32(0xFFFFFF00u) : dhcp_opt_mask;
        gateway_ip = ip_is_zero(dhcp_opt_router) ? dhcp_server : dhcp_opt_router;
        dns_ip = ip_is_zero(dhcp_opt_dns) ? gateway_ip : dhcp_opt_dns;
        configured = 1;
        console_printf("net: DHCP ok ip=%u.%u.%u.%u mask=%u.%u.%u.%u gw=%u.%u.%u.%u dns=%u.%u.%u.%u\n",
                       our_ip.b[0], our_ip.b[1], our_ip.b[2], our_ip.b[3],
                       netmask_ip.b[0], netmask_ip.b[1], netmask_ip.b[2], netmask_ip.b[3],
                       gateway_ip.b[0], gateway_ip.b[1], gateway_ip.b[2], gateway_ip.b[3],
                       dns_ip.b[0], dns_ip.b[1], dns_ip.b[2], dns_ip.b[3]);
        return 0;
    }
    dhcp_stage = 0;
    return -1;
}

/* ---- DNS ---- */
static u16 dns_id = 0;
static ip_t dns_result;
static int dns_done = 0;

/* Skip a DNS name at pos (labels + optional compression pointer).
   Returns the offset just past the name, or -1 on any malformed
   input (out of bounds, over-long label, pointer loop). */
static int dns_skip_name(const u8 *data, u32 len, u32 pos) {
    int jumps = 0;
    for (int steps = 0; steps < 128; steps++) {
        if (pos >= len) return -1;
        u8 b = data[pos];
        if (b == 0) return (int)pos + 1;
        if ((b & 0xC0) == 0xC0) {
            if (pos + 1 >= len) return -1;
            if (jumps++ > 8) return -1;
            /* A pointer terminates this name (this parser only
               skips names, never follows pointers, so a pointer
               loop cannot hang it — but the target must still
               be inside the packet: an out-of-bounds pointer is
               malformed and is rejected, not skipped blindly. */
            u32 target = ((u32)(b & 0x3F) << 8) | data[pos + 1];
            if (target >= len) return -1;
            return (int)pos + 2;
        }
        if (b > 63) return -1;
        if (pos + 1 + b > len) return -1;
        pos += 1 + b;
    }
    return -1;
}
static void dns_rx(const u8 *data, u32 len) {
    if (len < 12) { stack_drops++; return; }
    if (get16(data) != dns_id) return;
    u16 flags = get16(data + 2);
    if ((flags & 0x8000) == 0) return; /* must be a response */
    if ((flags & 0x000F) != 0) return; /* error response */
    int qd = get16(data + 4), an = get16(data + 6);
    u32 pos = 12;
    for (int i = 0; i < qd; i++) {
        int np = dns_skip_name(data, len, pos);
        if (np < 0 || (u32)np + 4 > len) { stack_drops++; return; }
        pos = (u32)np + 4;
    }
    for (int i = 0; i < an; i++) {
        int np = dns_skip_name(data, len, pos);
        if (np < 0 || (u32)np + 10 > len) { stack_drops++; return; }
        pos = (u32)np;
        u16 type = get16(data + pos);
        u16 rdlen = get16(data + pos + 8);
        pos += 10;
        if (pos + rdlen > len) { stack_drops++; return; }
        if (type == 1 && rdlen == 4) {
            memcpy(dns_result.b, data + pos, 4);
            dns_done = 1;
            return;
        }
        pos += rdlen; /* CNAME and others: skipped, A may follow */
    }
}
static int dns_encode_name(const char *name, u8 *out, u32 max) {
    u32 o = 0;
    int label_len_pos = 0, label_len = 0;
    /* Validate + encode. */
    if (!name[0]) return -1;
    out[o++] = 0; /* placeholder, fixed below per label */
    label_len_pos = 0;
    for (int i = 0; name[i]; i++) {
        char c = name[i];
        if (c == '.') {
            if (label_len == 0) return -1;
            out[label_len_pos] = (u8)label_len;
            if (o >= max) return -1;
            label_len_pos = (int)o;
            out[o++] = 0;
            label_len = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-')) return -1;
            if (label_len >= 63) return -1;
            if (o >= max) return -1;
            out[o++] = (u8)c;
            label_len++;
        }
    }
    if (label_len == 0) return -1;
    out[label_len_pos] = (u8)label_len;
    if (o >= max) return -1;
    out[o++] = 0;
    return (int)o;
}
int net_dns_lookup(const char *name, ip_t *out) {
    if (!configured || ip_is_zero(dns_ip)) return -1;
    u8 pkt[512];
    dns_id = (u16)(timer_ticks ^ 0x4E54u);
    dns_done = 0;
    put16(pkt, dns_id);
    put16(pkt + 2, 0x0100); /* recursion desired */
    put16(pkt + 4, 1); put16(pkt + 6, 0); put16(pkt + 8, 0); put16(pkt + 10, 0);
    int nlen = dns_encode_name(name, pkt + 12, sizeof(pkt) - 16);
    if (nlen < 0) return -1;
    u32 pos = 12 + (u32)nlen;
    put16(pkt + pos, 1); put16(pkt + pos + 2, 1); pos += 4;
    if (net_udp_send(dns_ip, 53, 5353, pkt, pos) != 0) return -1;
    u32 start = timer_ticks;
    while (timer_ticks - start < 300 && !dns_done) net_poll();
    if (!dns_done) return -1;
    *out = dns_result;
    return 0;
}

/* ---- HTTP (over TCP) ---- */
int net_parse_ip(const char *s, ip_t *out) {
    /* Returns 1 if s is a.b.c.d with each part 0-255, else 0. */
    int parts = 0, val = 0, digits = 0;
    for (int i = 0; ; i++) {
        char c = s[i];
        if (c >= '0' && c <= '9') {
            val = val * 10 + (c - '0');
            if (val > 255) return 0;
            digits++;
        } else if (c == '.' || c == 0) {
            if (digits == 0) return 0;
            out->b[parts++] = (u8)val;
            if (parts > 4) return 0;
            val = 0; digits = 0;
            if (c == 0) break;
        } else return 0;
    }
    return parts == 4;
}
int net_http_get(const char *host, u16 port, const char *path, char *buf, u32 max) {
    if (max < 2) return -1;
    ip_t hip;
    if (!net_parse_ip(host, &hip)) {
        if (net_dns_lookup(host, &hip) != 0) return -1;
    }
    if (net_tcp_connect(hip, port) != 0) return -1;
    char req[512];
    int ri = 0;
    const char *p;
    p = "GET "; while (*p) req[ri++] = *p++;
    p = path; while (*p && ri < 400) req[ri++] = *p++;
    p = " HTTP/1.0\r\nHost: "; while (*p) req[ri++] = *p++;
    p = host; while (*p && ri < 480) req[ri++] = *p++;
    p = "\r\n\r\n"; while (*p) req[ri++] = *p++;
    req[ri] = 0;
    if (net_tcp_send((const u8 *)req, (u32)ri) != 0) { net_tcp_close(); return -1; }
    /* Read until close or content-length satisfied. v0.10.0: a
       body larger than the buffer is TRUNCATED, not failed: the
       buffer fills, the rest is drained (so the completion check
       still works), and net_fetch_truncated() reports it. */
    fetch_truncated = 0;
    u8 tmp[1024];
    u32 total = 0, seen = 0, header_end = 0, content_len = 0xFFFFFFFFu;
    int storing = 1;
    u32 start = timer_ticks;
    while (timer_ticks - start < 1000) {
        int n = net_tcp_recv(tmp, sizeof(tmp), 100);
        if (n < 0) break; /* closed or error */
        if (n == 0) {
            /* Timeout slice with no data: keep waiting until
               the overall deadline, unless we already have a
               complete body. */
            if (header_end && content_len != 0xFFFFFFFFu &&
                seen >= header_end + content_len) break;
            continue;
        }
        seen += (u32)n;
        /* Append to buf (body extraction happens at the end
           from the raw stream kept in buf itself). */
        if (storing) {
            if (total + (u32)n > max - 1) {
                u32 room = max - 1 - total;
                if (room) { memcpy(buf + total, tmp, room); total += room; buf[total] = 0; }
                storing = 0; fetch_truncated = 1;
            } else {
                memcpy(buf + total, tmp, (u32)n);
                total += (u32)n;
                buf[total] = 0;
            }
        }
        if (!header_end) {
            for (u32 i = 0; i + 3 < total; i++) {
                if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
                    header_end = i + 4;
                    break;
                }
            }
            if (header_end) {
                /* Find Content-Length (case-sensitive "Content-Length:"
                   is what most simple servers send; also accept
                   lowercase by scanning for ": " after the name
                   case-insensitively is overkill here — HTTP/1.0
                   close-delimited bodies work without it). */
                for (u32 i = 0; i + 15 < header_end; i++) {
                    if ((buf[i]=='C' || buf[i]=='c') &&
                        memcmp(buf + i, "ontent-Length:", 14) == 0) {
                        u32 j = i + 15, v = 0;
                        while (j < header_end && buf[j] == ' ') j++;
                        while (j < header_end && buf[j] >= '0' && buf[j] <= '9') {
                            v = v * 10 + (u32)(buf[j] - '0'); j++;
                        }
                        content_len = v;
                        break;
                    }
                }
                /* Chunked transfer is not supported in v0.9.0:
                   HTTP/1.0 requests normally avoid it. */
                for (u32 i = 0; i + 17 < header_end; i++) {
                    if (memcmp(buf + i, "Transfer-Encoding:", 18) == 0) {
                        net_tcp_close(); return -1;
                    }
                }
            }
        }
        if (header_end && content_len != 0xFFFFFFFFu && seen >= header_end + content_len) break;
    }
    net_tcp_close();
    if (!header_end) return -1;
    u32 body_len = total - header_end;
    memmove(buf, buf + header_end, body_len);
    buf[body_len] = 0;
    return (int)body_len;
}
