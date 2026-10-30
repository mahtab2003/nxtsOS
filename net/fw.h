#ifndef NXTS_FW_H
#define NXTS_FW_H
#include "../kernel/common.h"
#include "net.h"

#define FW_MAX_RULES 16

/* One firewall rule. dir: 0 in, 1 out. action: 0 allow,
   1 deny. proto: 0 any, 1 ICMP, 6 TCP, 17 UDP (wire values,
   so matching is a direct comparison). *_any means the field
   is not constrained; otherwise the address must match
   exactly and the port must fall in [lo, hi]. */
struct fw_rule {
    int dir;
    int action;
    int proto;
    int src_any;  ip_t src;
    int sport_any; u16 sport_lo, sport_hi;
    int dst_any;  ip_t dst;
    int dport_any; u16 dport_lo, dport_hi;
};

/* Load fw.txt once per boot on first use (lazy: net_init runs
   before fs_mount, so boot load is impossible). A missing file
   means disabled + default allow; a file without headers means
   the same. Malformed lines are skipped, never fatal. */
void fw_lazy_load(void);
int  fw_enabled(void);
int  fw_default_deny(void); /* 1 = default deny, 0 = default allow */
u32  fw_drop_count(void);
int  fw_rule_count(void);
const struct fw_rule *fw_rule_at(int i);
/* 1 = allow, 0 = deny (and the drop counter is bumped on
   deny). No match -> default policy. When disabled, always
   allow and never count. */
int  fw_check(int dir, int proto, ip_t src, u16 sport, ip_t dst, u16 dport);
int  fw_add_rule(const struct fw_rule *r); /* 0 ok, -1 table full */
int  fw_del_rule(int idx); /* 0-based; 0 ok, -1 out of range */
void fw_clear_rules(void);
void fw_set_enabled(int en);
void fw_set_default(int deny);
int  fw_save(void); /* 0 ok, -1 no filesystem/error */
/* Field parsers (shell + file loader share them). */
int  fw_parse_ip(const char *s, ip_t *out); /* "any" or dotted quad */
int  fw_parse_port(const char *s, int *any, u16 *lo, u16 *hi);
/* "any", "80", "8000-8100"; 1 ok, 0 bad */
int  fw_parse_rule_line(const char *line, struct fw_rule *out);
/* Full 7-field rule line; 1 ok, 0 bad */
void fw_rule_to_str(const struct fw_rule *r, char *buf, u32 buf_size);

#endif
