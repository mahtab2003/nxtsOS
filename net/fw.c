/* nxtsOS firewall (core CLI family (e)): ordered rule table,
   first match wins, default policy on no match. Headers only
   — rules never match on payload contents. Filtering points
   are net_rx_frame (inbound, after src/dst/proto parsed and
   dst validated, before dispatch) and net_ip_send (outbound,
   before the packet is built). ARP is NOT filtered: it is the
   resolution layer the IP stack itself needs, and it carries
   no IP payload to policy on. When disabled, no filtering
   happens at all (check returns allow, counter untouched).
   Persistence is fw.txt, root-owned 0600 (it joins the
   system-file list, so a non-root user cannot plant one):
   header lines "#fw enabled=1" / "#fw default=deny" plus one
   rule per line, "in deny tcp any any any 80" (dir action
   proto src sport dst dport; ports "any", "80",
   "8000-8100"). Saved on every mutating command; loaded
   lazily on first use. Malformed lines are skipped silently
   (a load can happen on the packet path, where console
   output would spam the serial log); `fw list` shows exactly
   what loaded, so a skipped line is visible there by its
   absence. All buffers are file-scope: the kernel stack is
   16 KiB. */
#include "fw.h"
#include "net.h"
#include "../kernel/console.h"
#include "../fs/vfs.h"

static struct fw_rule fw_rules[FW_MAX_RULES];
static int fw_count = 0;
static int fw_on = 0;
static int fw_default = 0; /* 0 allow, 1 deny */
static u32 fw_drops = 0;
static int fw_loaded = 0;

/* Worst case fw.txt: 2 header lines + 16 rules x ~70 chars. */
static u8 fw_read_buf[2048];
static char fw_file_buf[2048];

static int streq(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == *b;
}

/* Bounded appends into fw_file_buf (save path). */
static void fw_putc(char c, u32 *p) {
    if (*p < sizeof(fw_file_buf) - 1) fw_file_buf[(*p)++] = c;
}
static void fw_puts(const char *s, u32 *p) {
    while (*s) fw_putc(*s++, p);
}

static int parse_u32_dec(const char *s, u32 *out) {
    u32 v = 0;
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
        if (v > (0xFFFFFFFFu - 9u) / 10u) return 0;
        v = v * 10u + (u32)(*p - '0');
    }
    *out = v;
    return 1;
}

int fw_parse_ip(const char *s, ip_t *out) {
    if (streq(s, "any")) return 2; /* any: caller sets *_any */
    return net_parse_ip(s, out) ? 1 : 0;
}

int fw_parse_port(const char *s, int *any, u16 *lo, u16 *hi) {
    if (streq(s, "any")) { *any = 1; *lo = 0; *hi = 0; return 1; }
    /* Single port, or lo-hi range. */
    const char *dash = 0;
    for (const char *p = s; *p; p++) if (*p == '-') { dash = p; break; }
    if (!dash) {
        u32 v = 0;
        if (!parse_u32_dec(s, &v) || v > 65535) return 0;
        *any = 0; *lo = (u16)v; *hi = (u16)v;
        return 1;
    }
    char left[16], right[16];
    u32 ll = (u32)(dash - s);
    if (ll == 0 || ll >= sizeof(left)) return 0;
    u32 rl = 0;
    while (dash[1 + rl]) rl++;
    if (rl == 0 || rl >= sizeof(right)) return 0;
    for (u32 i = 0; i < ll; i++) left[i] = s[i];
    left[ll] = 0;
    for (u32 i = 0; i < rl; i++) right[i] = dash[1 + i];
    right[rl] = 0;
    u32 a = 0, b = 0;
    if (!parse_u32_dec(left, &a) || !parse_u32_dec(right, &b)) return 0;
    if (a > 65535 || b > 65535 || a > b) return 0;
    *any = 0; *lo = (u16)a; *hi = (u16)b;
    return 1;
}

/* Split a line into words (space/tab separated). Returns the
   word count (at most maxw), or -1 if there are MORE words
   than maxw — extra words must make the line malformed, not
   silently ignored (an 8-word rule line is not a 7-word
   rule). Words point into a scratch copy. */
static char fw_words_buf[256];
static char *fw_words[8];
static int fw_split(char *line, int maxw) {
    u32 n = 0;
    while (line[n] && n < sizeof(fw_words_buf) - 1) {
        fw_words_buf[n] = line[n];
        n++;
    }
    fw_words_buf[n] = 0;
    int wc = 0;
    char *p = fw_words_buf;
    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        if (wc >= maxw) return -1;
        fw_words[wc++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) *p++ = 0;
    }
    return wc;
}

int fw_parse_rule_line(const char *line, struct fw_rule *out) {
    char tmp[256];
    u32 i = 0;
    while (line[i] && i < sizeof(tmp) - 1) { tmp[i] = line[i]; i++; }
    tmp[i] = 0;
    if (fw_split(tmp, 7) != 7) return 0;
    struct fw_rule r;
    memset(&r, 0, sizeof(r));
    if (streq(fw_words[0], "in")) r.dir = 0;
    else if (streq(fw_words[0], "out")) r.dir = 1;
    else return 0;
    if (streq(fw_words[1], "allow")) r.action = 0;
    else if (streq(fw_words[1], "deny")) r.action = 1;
    else return 0;
    if (streq(fw_words[2], "any")) r.proto = 0;
    else if (streq(fw_words[2], "icmp")) r.proto = 1;
    else if (streq(fw_words[2], "tcp")) r.proto = 6;
    else if (streq(fw_words[2], "udp")) r.proto = 17;
    else return 0;
    int rc = fw_parse_ip(fw_words[3], &r.src);
    if (rc == 0) return 0;
    r.src_any = (rc == 2);
    if (!fw_parse_port(fw_words[4], &r.sport_any, &r.sport_lo, &r.sport_hi)) return 0;
    rc = fw_parse_ip(fw_words[5], &r.dst);
    if (rc == 0) return 0;
    r.dst_any = (rc == 2);
    if (!fw_parse_port(fw_words[6], &r.dport_any, &r.dport_lo, &r.dport_hi)) return 0;
    *out = r;
    return 1;
}

void fw_rule_to_str(const struct fw_rule *r, char *buf, u32 buf_size) {
    u32 p = 0;
    const char *dir = r->dir ? "out" : "in";
    const char *act = r->action ? "deny" : "allow";
    const char *proto = r->proto == 1 ? "icmp" : r->proto == 6 ? "tcp" :
                        r->proto == 17 ? "udp" : "any";
    const char *parts[7];
    parts[0] = dir; parts[1] = act; parts[2] = proto;
    char srcb[20], dstb[20], sportb[20], dportb[20];
    if (r->src_any) parts[3] = "any";
    else {
        srcb[0] = 0;
        /* Dotted quad, no division (u32 division is forbidden). */
        u32 o = 0;
        for (int i = 0; i < 4; i++) {
            u32 v = r->src.b[i];
            char num[4];
            int nl = 0;
            if (v >= 100) { num[nl++] = (char)('0' + v / 100); v %= 100; }
            if (nl || v >= 10) { num[nl++] = (char)('0' + v / 10); v %= 10; }
            num[nl++] = (char)('0' + v);
            for (int j = 0; j < nl && o < sizeof(srcb) - 2; j++) srcb[o++] = num[j];
            if (i < 3) srcb[o++] = '.';
        }
        srcb[o] = 0;
        parts[3] = srcb;
    }
    if (r->dst_any) parts[5] = "any";
    else {
        u32 o = 0;
        for (int i = 0; i < 4; i++) {
            u32 v = r->dst.b[i];
            char num[4];
            int nl = 0;
            if (v >= 100) { num[nl++] = (char)('0' + v / 100); v %= 100; }
            if (nl || v >= 10) { num[nl++] = (char)('0' + v / 10); v %= 10; }
            num[nl++] = (char)('0' + v);
            for (int j = 0; j < nl && o < sizeof(dstb) - 2; j++) dstb[o++] = num[j];
            if (i < 3) dstb[o++] = '.';
        }
        dstb[o] = 0;
        parts[5] = dstb;
    }
    /* Ports: "any", "80", "8000-8100" (decimal, no division). */
    char *pb[2];
    u16 los[2], his[2];
    int anys[2];
    pb[0] = sportb; pb[1] = dportb;
    los[0] = r->sport_lo; his[0] = r->sport_hi; anys[0] = r->sport_any;
    los[1] = r->dport_lo; his[1] = r->dport_hi; anys[1] = r->dport_any;
    for (int k = 0; k < 2; k++) {
        if (anys[k]) { pb[k][0] = 'a'; pb[k][1] = 'n'; pb[k][2] = 'y'; pb[k][3] = 0; continue; }
        u32 o = 0;
        u16 vals[2];
        int nv = (los[k] == his[k]) ? 1 : 2;
        vals[0] = los[k]; vals[1] = his[k];
        for (int vi = 0; vi < nv; vi++) {
            u32 v = vals[vi];
            char num[6];
            int nl = 0;
            if (v >= 10000) { num[nl++] = (char)('0' + v / 10000); v %= 10000; }
            if (nl || v >= 1000) { num[nl++] = (char)('0' + v / 1000); v %= 1000; }
            if (nl || v >= 100) { num[nl++] = (char)('0' + v / 100); v %= 100; }
            if (nl || v >= 10) { num[nl++] = (char)('0' + v / 10); v %= 10; }
            num[nl++] = (char)('0' + v);
            for (int j = 0; j < nl && o < 18; j++) pb[k][o++] = num[j];
            if (vi == 0 && nv == 2) pb[k][o++] = '-';
        }
        pb[k][o] = 0;
    }
    parts[4] = sportb; parts[6] = dportb;
    for (int i = 0; i < 7; i++) {
        if (i) { if (p < buf_size - 1) buf[p++] = ' '; }
        const char *w = parts[i];
        while (*w && p < buf_size - 1) buf[p++] = *w++;
    }
    buf[p] = 0;
}

void fw_lazy_load(void) {
    if (fw_loaded) return;
    if (!fs_mounted()) return; /* retry on the next use */
    fw_count = 0; fw_on = 0; fw_default = 0;
    u32 size = 0;
    if (fs_read("fw.txt", fw_read_buf, sizeof(fw_read_buf) - 1, &size) != 0) {
        fw_loaded = 1; /* no file: defaults stand */
        return;
    }
    fw_read_buf[size] = 0;
    u32 pos = 0;
    while (pos < size) {
        u32 ls = pos;
        while (pos < size && fw_read_buf[pos] != '\n') pos++;
        u32 ll = pos - ls;
        if (pos < size) pos++;
        if (ll == 0) continue;
        if (fw_read_buf[ls] == '#') {
            /* Header lines: "#fw enabled=1", "#fw default=deny". */
            char line[64];
            u32 n = ll < sizeof(line) - 1 ? ll : sizeof(line) - 1;
            for (u32 i = 0; i < n; i++) line[i] = (char)fw_read_buf[ls + i];
            line[n] = 0;
            if (streq(line, "#fw enabled=1")) fw_on = 1;
            else if (streq(line, "#fw enabled=0")) fw_on = 0;
            else if (streq(line, "#fw default=deny")) fw_default = 1;
            else if (streq(line, "#fw default=allow")) fw_default = 0;
            continue;
        }
        if (ll >= 256) continue; /* overlong: skipped, never fatal */
        char line[256];
        for (u32 i = 0; i < ll; i++) line[i] = (char)fw_read_buf[ls + i];
        line[ll] = 0;
        struct fw_rule r;
        if (fw_parse_rule_line(line, &r) && fw_count < FW_MAX_RULES)
            fw_rules[fw_count++] = r;
        /* Malformed or over-capacity lines are skipped. */
    }
    fw_loaded = 1;
}

int fw_enabled(void) { fw_lazy_load(); return fw_on; }
int fw_default_deny(void) { fw_lazy_load(); return fw_default; }
u32 fw_drop_count(void) { fw_lazy_load(); return fw_drops; }
int fw_rule_count(void) { fw_lazy_load(); return fw_count; }
const struct fw_rule *fw_rule_at(int i) {
    fw_lazy_load();
    if (i < 0 || i >= fw_count) return 0;
    return &fw_rules[i];
}

int fw_check(int dir, int proto, ip_t src, u16 sport, ip_t dst, u16 dport) {
    fw_lazy_load();
    if (!fw_on) return 1;
    for (int i = 0; i < fw_count; i++) {
        const struct fw_rule *r = &fw_rules[i];
        if (r->dir != dir) continue;
        if (r->proto != 0 && r->proto != proto) continue;
        if (!r->src_any && !ip_equal(r->src, src)) continue;
        if (!r->sport_any && (sport < r->sport_lo || sport > r->sport_hi)) continue;
        if (!r->dst_any && !ip_equal(r->dst, dst)) continue;
        if (!r->dport_any && (dport < r->dport_lo || dport > r->dport_hi)) continue;
        if (r->action == 1) fw_drops++;
        return r->action == 0;
    }
    if (fw_default) fw_drops++;
    return fw_default == 0;
}

int fw_add_rule(const struct fw_rule *r) {
    fw_lazy_load();
    if (fw_count >= FW_MAX_RULES) return -1;
    fw_rules[fw_count++] = *r;
    return 0;
}

int fw_del_rule(int idx) {
    fw_lazy_load();
    if (idx < 0 || idx >= fw_count) return -1;
    for (int i = idx; i + 1 < fw_count; i++) fw_rules[i] = fw_rules[i + 1];
    fw_count--;
    return 0;
}

void fw_clear_rules(void) { fw_lazy_load(); fw_count = 0; }
void fw_set_enabled(int en) { fw_lazy_load(); fw_on = en ? 1 : 0; }
void fw_set_default(int deny) { fw_lazy_load(); fw_default = deny ? 1 : 0; }

int fw_save(void) {
    fw_lazy_load();
    if (!fs_mounted()) return -1;
    u32 p = 0;
    /* Bounded appends: every write checks first, so no
       overflow is possible regardless of rule count. */
    fw_puts("#fw enabled=", &p);
    fw_putc(fw_on ? '1' : '0', &p);
    fw_putc('\n', &p);
    fw_puts("#fw default=", &p);
    fw_puts(fw_default ? "deny\n" : "allow\n", &p);
    for (int i = 0; i < fw_count; i++) {
        char line[128];
        fw_rule_to_str(&fw_rules[i], line, sizeof(line));
        fw_puts(line, &p);
        fw_putc('\n', &p);
    }
    /* Root-owned 0600: fw.txt joins the system-file list, so a
       non-root user can never plant a policy. */
    return fs_write_as("fw.txt", (const u8 *)fw_file_buf, p, 0, 0600);
}
