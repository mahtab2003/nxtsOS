#include "users.h"
#include "console.h"
#include "../fs/vfs.h"

struct user_rec {
    char name[32];
    u32 uid;
    char salt[16];
    u32 hash;
};
static struct user_rec users[MAX_USERS];
static int user_count = 0;

/* v0.4.1 password hash: salted FNV-1a iterated 10000 times.
   The work factor makes each guess ~10000x more expensive than the
   v0.4.0 single-round hash, so short passwords are no longer trivially
   brute-forceable offline. It is still NOT a production KDF: it has no
   memory hardness (no bcrypt/scrypt/Argon2), so a well-resourced
   attacker with the disk can still brute-force weak passwords, just
   much more slowly. That limit is documented in docs/SECURITY.md.
   BREAKING CHANGE vs v0.4.0: single-round hashes will not match.
   Regenerate users.txt with the updated tools/mkuser.py.
   The iteration count must match mkuser.py exactly. */
#define USERS_HASH_ITERATIONS 10000
static u32 fnv_step(u32 h, const u8 *data, u32 len) {
    for (u32 i = 0; i < len; i++) { h ^= data[i]; h *= 16777619u; }
    return h;
}
u32 users_hash(const char *salt, const char *password) {
    u32 h = 2166136261u;
    h = fnv_step(h, (const u8 *)salt, strlen(salt));
    h = fnv_step(h, (const u8 *)password, strlen(password));
    for (int i = 0; i < USERS_HASH_ITERATIONS; i++) {
        u8 buf[24];
        u32 j = 0;
        const char *p = salt;
        while (*p && j < 16) buf[j++] = (u8)*p++;
        buf[j++] = (u8)(h & 0xFF); buf[j++] = (u8)((h >> 8) & 0xFF);
        buf[j++] = (u8)((h >> 16) & 0xFF); buf[j++] = (u8)((h >> 24) & 0xFF);
        h = 2166136261u;
        h = fnv_step(h, buf, j);
    }
    return h;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
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

int users_count(void) { return user_count; }

int users_load(void) {
    user_count = 0;
    if (!fs_mounted()) return 0;
    u8 buf[2048];
    u32 size = 0;
    if (fs_read("users.txt", buf, sizeof(buf) - 1, &size) != 0) return 0;
    buf[size] = 0;
    u32 pos = 0;
    while (pos < size && user_count < MAX_USERS) {
        u32 line_start = pos;
        while (pos < size && buf[pos] != '\n') pos++;
        u32 line_len = pos - line_start;
        if (pos < size) pos++; /* skip newline */
        if (line_len == 0) continue;
        /* Split name:uid:salt:hashhex */
        int c1 = -1, c2 = -1, c3 = -1;
        for (u32 i = 0; i < line_len; i++) {
            if (buf[line_start + i] == ':') {
                if (c1 < 0) c1 = (int)i;
                else if (c2 < 0) c2 = (int)i;
                else if (c3 < 0) c3 = (int)i;
                else break;
            }
        }
        if (c1 <= 0 || c2 <= c1 + 1 || c3 <= c2 + 1 || c3 >= (int)line_len) {
            console_write("users: skipping malformed line\n");
            continue;
        }
        u32 name_len = (u32)c1;
        u32 uid_len = (u32)(c2 - c1 - 1);
        u32 salt_len = (u32)(c3 - c2 - 1);
        u32 hash_len = line_len - (u32)c3 - 1;
        if (name_len >= 32 || salt_len >= 16 || hash_len != 8) {
            console_write("users: skipping malformed line\n");
            continue;
        }
        u32 uid = 0;
        if (parse_u32_dec((const char *)buf + line_start + c1 + 1, uid_len, &uid) != 0 || uid > 100000) {
            console_write("users: skipping line with bad uid\n");
            continue;
        }
        u32 hash = 0;
        int bad = 0;
        for (u32 i = 0; i < 8; i++) {
            int v = hex_val((char)buf[line_start + c3 + 1 + i]);
            if (v < 0) { bad = 1; break; }
            hash = (hash << 4) | (u32)v;
        }
        if (bad) { console_write("users: skipping line with bad hash\n"); continue; }
        struct user_rec *u = &users[user_count];
        memset(u, 0, sizeof(*u));
        memcpy(u->name, buf + line_start, name_len);
        memcpy(u->salt, buf + line_start + c2 + 1, salt_len);
        u->uid = uid; u->hash = hash;
        user_count++;
    }
    return user_count;
}

int users_check(const char *name, const char *password, u32 *uid_out) {
    if (!password || password[0] == 0) return 0; /* empty passwords never match */
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].name, name) == 0) {
            if (users_hash(users[i].salt, password) == users[i].hash) {
                *uid_out = users[i].uid;
                return 1;
            }
            return 0;
        }
    }
    return 0;
}

const char *users_name_for_uid(u32 uid) {
    for (int i = 0; i < user_count; i++)
        if (users[i].uid == uid) return users[i].name;
    return uid == 0 ? "root" : "unknown";
}
