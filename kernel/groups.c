#include "groups.h"
#include "users.h"
#include "console.h"
#include "../fs/vfs.h"

struct group_rec {
    char name[32];
    u32 gid;
    char members[MAX_GROUP_MEMBERS][32];
    int member_count;
};
static struct group_rec groups[MAX_GROUPS];
static int group_count = 0;

/* Worst case groups.txt: 8 groups x (31 name + 1 + 6 gid + 1 +
   8 members x 31 + 7 commas + 1 newline) = 2360 bytes. The
   buffers are file-scope, never stack: the kernel stack is
   16 KiB. */
static u8 groups_read_buf[4096];
static char groups_file_buf[4096];

static int parse_u32_dec(const char *s, u32 len, u32 *out) {
    u32 v = 0;
    if (len == 0) return -1;
    for (u32 i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        if (v > (0xFFFFFFFFu - 9u) / 10u) return -1;
        v = v * 10u + (u32)(s[i] - '0');
    }
    *out = v;
    return 0;
}

int groups_count(void) { return group_count; }

int groups_load(void) {
    group_count = 0;
    if (!fs_mounted()) return 0;
    u32 size = 0;
    if (fs_read("groups.txt", groups_read_buf, sizeof(groups_read_buf) - 1, &size) != 0)
        return 0;
    groups_read_buf[size] = 0;
    u32 pos = 0;
    while (pos < size && group_count < MAX_GROUPS) {
        u32 line_start = pos;
        while (pos < size && groups_read_buf[pos] != '\n') pos++;
        u32 line_len = pos - line_start;
        if (pos < size) pos++; /* skip newline */
        if (line_len == 0) continue;
        /* Split name:gid:members */
        int c1 = -1, c2 = -1;
        for (u32 i = 0; i < line_len; i++) {
            if (groups_read_buf[line_start + i] == ':') {
                if (c1 < 0) c1 = (int)i;
                else if (c2 < 0) c2 = (int)i;
                else break;
            }
        }
        if (c1 <= 0 || c2 <= c1 + 1) {
            console_write("groups: skipping malformed line\n");
            continue;
        }
        u32 name_len = (u32)c1;
        u32 gid_len = (u32)(c2 - c1 - 1);
        if (name_len >= 32) { console_write("groups: skipping malformed line\n"); continue; }
        char name[32];
        memset(name, 0, sizeof(name));
        memcpy(name, groups_read_buf + line_start, name_len);
        if (!users_valid_name(name)) { console_write("groups: skipping malformed line\n"); continue; }
        u32 gid = 0;
        if (parse_u32_dec((const char *)groups_read_buf + line_start + c1 + 1, gid_len, &gid) != 0
            || gid < 1000 || gid > 100000) {
            console_write("groups: skipping line with bad gid\n");
            continue;
        }
        /* Members: comma-separated names, possibly empty. A bad
           member skips the whole line, matching users_load's
           discipline for malformed lines. */
        struct group_rec *g = &groups[group_count];
        memset(g, 0, sizeof(*g));
        memcpy(g->name, name, name_len);
        g->gid = gid;
        u32 mpos = line_start + (u32)c2 + 1;
        u32 mend = line_start + line_len;
        int bad = 0;
        while (mpos < mend) {
            u32 mstart = mpos;
            while (mpos < mend && groups_read_buf[mpos] != ',') mpos++;
            u32 mlen = mpos - mstart;
            if (mpos < mend) mpos++; /* skip comma */
            if (mlen == 0 || mlen >= 32) { bad = 1; break; }
            if (g->member_count >= MAX_GROUP_MEMBERS) { bad = 1; break; }
            char member[32];
            memset(member, 0, sizeof(member));
            memcpy(member, groups_read_buf + mstart, mlen);
            if (!users_valid_name(member) && strcmp(member, "root") != 0) { bad = 1; break; }
            /* Duplicate members in one line collapse silently: the
               file is root-written, so a duplicate is a hand edit,
               not an attack, and membership is a set. */
            int dup = 0;
            for (int i = 0; i < g->member_count; i++)
                if (strcmp(g->members[i], member) == 0) { dup = 1; break; }
            if (!dup) {
                memcpy(g->members[g->member_count], member, mlen);
                g->member_count++;
            }
        }
        if (bad) { console_write("groups: skipping malformed line\n"); continue; }
        group_count++;
    }
    return group_count;
}

int groups_exists(const char *name) {
    if (!name) return 0;
    if (fs_mounted()) groups_load();
    for (int i = 0; i < group_count; i++)
        if (strcmp(groups[i].name, name) == 0) return 1;
    return 0;
}

int groups_gid(const char *name, u32 *gid_out) {
    if (!name || !gid_out) return -1;
    /* Read-only accessors must see a pre-seeded groups.txt even
       when no group mutator has run this boot (sudo/chgrp hit
       this: the table was empty until a mutator loaded it). */
    if (fs_mounted()) groups_load();
    for (int i = 0; i < group_count; i++)
        if (strcmp(groups[i].name, name) == 0) { *gid_out = groups[i].gid; return 0; }
    return -1;
}

static int groups_overflow = 0;
static void gbuf_putc(char *buf, u32 *pos, char c) {
    if (*pos < sizeof(groups_file_buf) - 1) buf[(*pos)++] = c;
    else groups_overflow = 1; /* truncated input: the caller refuses the write */
}
static void gbuf_puts(char *buf, u32 *pos, const char *s) {
    while (*s) gbuf_putc(buf, pos, *s++);
}
static void gbuf_put_u32(char *buf, u32 *pos, u32 v) {
    char rev[10]; int n = 0;
    if (v == 0) rev[n++] = '0';
    else while (v > 0) { rev[n++] = (char)('0' + (v % 10u)); v /= 10u; }
    while (n > 0) gbuf_putc(buf, pos, rev[--n]);
}

/* Rewrite groups.txt from the loaded table. Returns 0 on success,
   -1 on overflow or write failure. Callers reload + verify after. */
static int groups_rewrite(void) {
    u32 pos = 0;
    groups_overflow = 0;
    for (int i = 0; i < group_count; i++) {
        gbuf_puts(groups_file_buf, &pos, groups[i].name);
        gbuf_putc(groups_file_buf, &pos, ':');
        gbuf_put_u32(groups_file_buf, &pos, groups[i].gid);
        gbuf_putc(groups_file_buf, &pos, ':');
        for (int m = 0; m < groups[i].member_count; m++) {
            if (m > 0) gbuf_putc(groups_file_buf, &pos, ',');
            gbuf_puts(groups_file_buf, &pos, groups[i].members[m]);
        }
        gbuf_putc(groups_file_buf, &pos, '\n');
    }
    if (groups_overflow) return -1;
    if (fs_write_as("groups.txt", (const u8 *)groups_file_buf, pos, 0, 0600) != 0)
        return -1;
    return 0;
}

int groups_add(const char *name) {
    if (!users_valid_name(name)) return -1;
    if (!fs_mounted()) return -1;
    if (fs_exists("groups.txt")) groups_load();
    else group_count = 0;
    if (groups_exists(name)) return -1;
    if (group_count >= MAX_GROUPS) return -1;
    u32 gid = 1000;
    for (int i = 0; i < group_count; i++)
        if (groups[i].gid >= gid) gid = groups[i].gid + 1;
    if (gid > 100000) return -1; /* groups_load would skip it on reload */
    struct group_rec *g = &groups[group_count];
    memset(g, 0, sizeof(*g));
    u32 nl = 0;
    while (name[nl] && nl < 31) { g->name[nl] = name[nl]; nl++; }
    g->gid = gid;
    g->member_count = 0;
    group_count++;
    if (groups_rewrite() != 0) return -1;
    groups_load();
    u32 check = 0;
    if (groups_gid(name, &check) != 0 || check != gid) return -1;
    return (int)gid;
}

int groups_delete(const char *name) {
    if (!name || !fs_mounted()) return -1;
    groups_load();
    int idx = -1;
    for (int i = 0; i < group_count; i++)
        if (strcmp(groups[i].name, name) == 0) { idx = i; break; }
    if (idx < 0) return -1;
    for (int i = idx; i + 1 < group_count; i++) groups[i] = groups[i + 1];
    group_count--;
    if (groups_rewrite() != 0) return -1;
    groups_load();
    if (groups_exists(name)) return -1;
    return 0;
}

static int groups_mod(const char *group, const char *user, int add) {
    if (!group || !user || !fs_mounted()) return -1;
    groups_load();
    users_load(); /* refresh: membership needs a current account table */
    /* The user must be a real account. users_exists covers loaded
       accounts; "root" is implicit (uid 0) and may hold membership
       like any other identity. */
    if (!users_exists(user) && strcmp(user, "root") != 0) return -1;
    int idx = -1;
    for (int i = 0; i < group_count; i++)
        if (strcmp(groups[i].name, group) == 0) { idx = i; break; }
    if (idx < 0) return -1;
    struct group_rec *g = &groups[idx];
    int midx = -1;
    for (int m = 0; m < g->member_count; m++)
        if (strcmp(g->members[m], user) == 0) { midx = m; break; }
    if (add) {
        if (midx >= 0) return 1; /* already a member: report, don't pretend */
        if (g->member_count >= MAX_GROUP_MEMBERS) return -2;
        u32 nl = 0;
        while (user[nl] && nl < 31) { g->members[g->member_count][nl] = user[nl]; nl++; }
        g->member_count++;
    } else {
        if (midx < 0) return 1; /* not a member: report, don't pretend */
        for (int m = midx; m + 1 < g->member_count; m++)
            memcpy(g->members[m], g->members[m + 1], 32);
        memset(g->members[g->member_count - 1], 0, 32);
        g->member_count--;
    }
    if (groups_rewrite() != 0) return -1;
    groups_load();
    /* Verify the change landed. */
    int nidx = -1;
    for (int i = 0; i < group_count; i++)
        if (strcmp(groups[i].name, group) == 0) { nidx = i; break; }
    if (nidx < 0) return -1;
    int found = 0;
    for (int m = 0; m < groups[nidx].member_count; m++)
        if (strcmp(groups[nidx].members[m], user) == 0) found = 1;
    if (add && !found) return -1;
    if (!add && found) return -1;
    return 0;
}

int groups_mod_add(const char *group, const char *user) {
    return groups_mod(group, user, 1);
}
int groups_mod_remove(const char *group, const char *user) {
    return groups_mod(group, user, 0);
}

int groups_names_for_user(const char *user, char *out, u32 cap) {
    if (!user || !out || cap == 0) return -1;
    groups_load();
    out[0] = 0;
    u32 pos = 0;
    int count = 0;
    for (int i = 0; i < group_count; i++) {
        int member = 0;
        for (int m = 0; m < groups[i].member_count; m++)
            if (strcmp(groups[i].members[m], user) == 0) { member = 1; break; }
        if (!member) continue;
        u32 nl = strlen(groups[i].name);
        if (pos + (count > 0 ? 1 : 0) + nl + 1 > cap) return -1;
        if (count > 0) out[pos++] = ',';
        memcpy(out + pos, groups[i].name, nl);
        pos += nl;
        count++;
    }
    out[pos] = 0;
    return count;
}

/* Parity run: group permission helpers. Both load groups.txt
   fresh, so groupmod takes effect immediately. No recursion
   risk: groups_load reads via fs_read (uid 0), and the fs
   permission rules return at the root check before ever
   consulting membership. */
u32 groups_primary_gid(u32 uid) {
    if (fs_mounted()) groups_load();
    if (uid == 0) return 0;
    const char *name = users_name_for_uid(uid);
    if (!name || strcmp(name, "unknown") == 0) return 0;
    groups_load();
    for (int i = 0; i < group_count; i++) {
        for (int m = 0; m < groups[i].member_count; m++)
            if (strcmp(groups[i].members[m], name) == 0) return groups[i].gid;
    }
    return 0;
}

int groups_user_in_gid(u32 uid, u32 gid) {
    if (gid == 0) return 0;
    const char *name = users_name_for_uid(uid);
    if (!name || strcmp(name, "unknown") == 0) return 0;
    groups_load();
    for (int i = 0; i < group_count; i++) {
        if (groups[i].gid != gid) continue;
        for (int m = 0; m < groups[i].member_count; m++)
            if (strcmp(groups[i].members[m], name) == 0) return 1;
        return 0;
    }
    return 0;
}

int groups_name_for_gid(u32 gid, char *out, u32 cap) {
    if (!out || cap == 0) return -1;
    groups_load();
    for (int i = 0; i < group_count; i++) {
        if (groups[i].gid != gid) continue;
        u32 j = 0;
        while (groups[i].name[j] && j + 1 < cap) { out[j] = groups[i].name[j]; j++; }
        out[j] = 0;
        return 0;
    }
    return -1;
}
