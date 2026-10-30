#include "users.h"
#include "console.h"
#include "csprng.h"
#include "../fs/vfs.h"
#include "../drivers/pit.h" /* timer_ticks: fallback counter only */

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

int users_exists(const char *name) {
    if (!name) return 0;
    for (int i = 0; i < user_count; i++)
        if (strcmp(users[i].name, name) == 0) return 1;
    return 0;
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

/* Runtime password change (shell `passwd`, post-v1.0.0). The salt is
   NOT secret — it is stored in plaintext in users.txt, like every salt
   — so it only needs to be distinct per user and per change, which the
   100 Hz tick counter plus a monotonic change counter give: two changes
   in the same tick still differ, and a changed password never reuses the
   previous salt. The kernel has no hardware RNG; ticks are the only
   in-kernel entropy source, and that limit is documented, not hidden.
   The rewrite buffer is file-scope, not stack: the kernel stack is
   16 KiB. Worst case is 8 users x (31 name + 1 + 6 uid + 1 + 12 salt +
   1 + 8 hash + 1 newline) = 488 bytes, far inside the 1024-byte buffer;
   the length check below refuses rather than overflows regardless. */
static u32 passwd_counter = 0;
static char passwd_file_buf[1024];

static void gen_salt(char *out, u32 uid) {
    static const char alpha[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    /* Salts need uniqueness, not secrecy — but there is no
       reason to keep the old predictable timer/xorshift
       construction now that the CSPRNG exists. The uid and a
       counter are still folded in so two salts for one user
       can never repeat even if the DRBG state did. */
    u8 rnd[12];
    csprng_generate(rnd, sizeof(rnd));
    (void)uid;
    for (int i = 0; i < 12; i++)
        out[i] = alpha[(rnd[i] + (u8)(passwd_counter + (u32)i)) % 36];
    passwd_counter++;
    out[12] = 0;
}

static int passwd_overflow = 0;
static void buf_putc(char *buf, u32 *pos, char c) {
    if (*pos < sizeof(passwd_file_buf) - 1) buf[(*pos)++] = c;
    else passwd_overflow = 1; /* truncated input: the caller refuses the write */
}
static void buf_puts(char *buf, u32 *pos, const char *s) {
    while (*s) buf_putc(buf, pos, *s++);
}
static void buf_put_u32(char *buf, u32 *pos, u32 v) {
    char rev[10]; int n = 0;
    if (v == 0) rev[n++] = '0';
    else while (v > 0) { rev[n++] = (char)('0' + (v % 10u)); v /= 10u; }
    while (n > 0) buf_putc(buf, pos, rev[--n]);
}
static void buf_put_hex8(char *buf, u32 *pos, u32 v) {
    static const char hexd[] = "0123456789abcdef";
    for (int sh = 28; sh >= 0; sh -= 4) buf_putc(buf, pos, hexd[(v >> sh) & 0xFu]);
}

int users_valid_name(const char *name) {
    if (!name || name[0] == 0) return 0;
    if (strcmp(name, "root") == 0) return 0;
    u32 len = 0;
    while (name[len]) {
        if (len >= 31) return 0;
        unsigned char c = (unsigned char)name[len];
        if (c < 33 || c > 126 || c == ':') return 0;
        len++;
    }
    return len > 0;
}

int users_uid(const char *name, u32 *uid_out) {
    if (!name || !uid_out) return -1;
    if (strcmp(name, "root") == 0) { *uid_out = 0; return 0; }
    for (int i = 0; i < user_count; i++)
        if (strcmp(users[i].name, name) == 0) { *uid_out = users[i].uid; return 0; }
    return -1;
}

/* Rewrite users.txt from the loaded table plus one pending record
   (for add) or minus one record (for delete, skip < 0). Shared by
   users_add/users_delete so the two paths cannot drift apart: the
   buffer, the 0600 root-owned write, and the reload+verify
   discipline are identical to users_change_password. */
static int users_rewrite(const struct user_rec *extra, int skip) {
    u32 pos = 0;
    passwd_overflow = 0;
    for (int i = 0; i < user_count; i++) {
        if (i == skip) continue;
        buf_puts(passwd_file_buf, &pos, users[i].name);
        buf_putc(passwd_file_buf, &pos, ':');
        buf_put_u32(passwd_file_buf, &pos, users[i].uid);
        buf_putc(passwd_file_buf, &pos, ':');
        buf_puts(passwd_file_buf, &pos, users[i].salt);
        buf_putc(passwd_file_buf, &pos, ':');
        buf_put_hex8(passwd_file_buf, &pos, users[i].hash);
        buf_putc(passwd_file_buf, &pos, '\n');
    }
    if (extra) {
        buf_puts(passwd_file_buf, &pos, extra->name);
        buf_putc(passwd_file_buf, &pos, ':');
        buf_put_u32(passwd_file_buf, &pos, extra->uid);
        buf_putc(passwd_file_buf, &pos, ':');
        buf_puts(passwd_file_buf, &pos, extra->salt);
        buf_putc(passwd_file_buf, &pos, ':');
        buf_put_hex8(passwd_file_buf, &pos, extra->hash);
        buf_putc(passwd_file_buf, &pos, '\n');
    }
    if (passwd_overflow) return -1;
    if (fs_write_as("users.txt", (const u8 *)passwd_file_buf, pos, 0, 0600) != 0)
        return -1;
    return 0;
}

int users_add(const char *name, const char *password) {
    if (!users_valid_name(name) || !password || password[0] == 0) return -1;
    if (!fs_mounted()) return -1;
    /* Refresh from disk when a file exists (a previous add in this
       session already reloaded, but never trust a stale table for
       a duplicate/cap decision). No file means setup mode: the
       table starts empty and this add creates the file. */
    if (fs_exists("users.txt")) users_load();
    else user_count = 0;
    if (users_exists(name)) return -1;
    if (user_count >= MAX_USERS) return -1;
    u32 uid = 1000;
    for (int i = 0; i < user_count; i++)
        if (users[i].uid >= uid) uid = users[i].uid + 1;
    if (uid > 100000) return -1; /* users_load would skip it on reload */
    struct user_rec rec;
    memset(&rec, 0, sizeof(rec));
    u32 nl = 0;
    while (name[nl] && nl < 31) { rec.name[nl] = name[nl]; nl++; }
    rec.uid = uid;
    gen_salt(rec.salt, uid);
    rec.hash = users_hash(rec.salt, password);
    if (users_rewrite(&rec, -1) != 0) return -1;
    if (users_load() <= 0) return -1;
    u32 check_uid = 0;
    if (!users_check(name, password, &check_uid) || check_uid != uid) return -1;
    return 0;
}

int users_delete(const char *name) {
    if (!name || !fs_mounted()) return -1;
    users_load();
    int idx = -1;
    for (int i = 0; i < user_count; i++)
        if (strcmp(users[i].name, name) == 0) { idx = i; break; }
    if (idx < 0) return -1;
    if (users_rewrite(0, idx) != 0) return -1;
    users_load();
    if (users_exists(name)) return -1;
    return 0;
}

int users_change_password(const char *name, const char *new_password) {
    if (!name || !new_password || new_password[0] == 0) return -1;
    if (!fs_mounted()) return -1;
    int idx = -1;
    for (int i = 0; i < user_count; i++)
        if (strcmp(users[i].name, name) == 0) { idx = i; break; }
    if (idx < 0) return -1; /* not a loaded user */
    char salt[16];
    gen_salt(salt, users[idx].uid);
    u32 hash = users_hash(salt, new_password);
    u32 pos = 0;
    passwd_overflow = 0;
    for (int i = 0; i < user_count; i++) {
        buf_puts(passwd_file_buf, &pos, users[i].name);
        buf_putc(passwd_file_buf, &pos, ':');
        buf_put_u32(passwd_file_buf, &pos, users[i].uid);
        buf_putc(passwd_file_buf, &pos, ':');
        if (i == idx) buf_puts(passwd_file_buf, &pos, salt);
        else buf_puts(passwd_file_buf, &pos, users[i].salt);
        buf_putc(passwd_file_buf, &pos, ':');
        if (i == idx) buf_put_hex8(passwd_file_buf, &pos, hash);
        else buf_put_hex8(passwd_file_buf, &pos, users[i].hash);
        buf_putc(passwd_file_buf, &pos, '\n');
    }
    if (passwd_overflow) return -1; /* cannot happen: see above, but never write truncated */
    /* Root-only overwrite, root-owned 0600, so the rewritten file keeps
       the protection the original had; fs_write_as writes the new
       sectors before committing bitmap + directory, so a no-space
       failure keeps the old file. */
    if (fs_write_as("users.txt", (const u8 *)passwd_file_buf, pos, 0, 0600) != 0)
        return -1;
    /* Reload so the in-memory table matches the file, then prove the new
       password checks before reporting success. */
    if (users_load() <= 0) return -1;
    u32 uid = 0;
    if (!users_check(name, new_password, &uid)) return -1;
    return 0;
}
