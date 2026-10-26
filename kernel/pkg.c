#include "pkg.h"
#include "sha256.h"
#include "console.h"
#include "../fs/vfs.h"

#define PKG_MAX_SIZE 131072
#define PKG_MAX_FILES 8
#define PKG_MAX_PKGS 8
#define REG_MAX 2048

static u8 pkg_buf[PKG_MAX_SIZE];

struct pkg_file { char name[32]; u32 size; u8 hash[32]; u32 blob_off; };
struct pkg_manifest {
    char name[32]; char version[16]; char depends[128];
    struct pkg_file files[PKG_MAX_FILES]; int nfiles;
};
struct reg_pkg {
    char name[32]; char version[16]; char depends[128];
    char files[PKG_MAX_FILES][32]; u8 hashes[PKG_MAX_FILES][32]; int nfiles;
};
static struct reg_pkg registry[PKG_MAX_PKGS];
static int reg_count = 0;

static int valid_pkg_name(const char *s) {
    u32 len = strlen(s);
    if (len == 0 || len >= 32) return 0;
    if (s[0] < 'a' || s[0] > 'z') return 0;
    for (u32 i = 0; i < len; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) return 0;
    }
    return 1;
}
static int valid_version(const char *s) {
    u32 len = strlen(s);
    if (len == 0 || len >= 16) return 0;
    if (s[0] == '.' || s[len-1] == '.') return 0;
    int digit = 0;
    for (u32 i = 0; i < len; i++) {
        char c = s[i];
        if (c >= '0' && c <= '9') digit = 1;
        else if (c == '.') { if (i > 0 && s[i-1] == '.') return 0; }
        else return 0;
    }
    return digit;
}
static int valid_file_name(const char *s) {
    u32 len = strlen(s);
    if (len == 0 || len >= 32) return 0;
    if (strcmp(s, "packages.txt") == 0 || strcmp(s, "users.txt") == 0 ||
        strcmp(s, "audit.log") == 0 || strcmp(s, "fails.txt") == 0) return 0;
    /* No .nxpkg files inside a package (they are installers, not payloads). */
    if (len > 6 && strcmp(s + len - 6, ".nxpkg") == 0) return 0;
    for (u32 i = 0; i < len; i++) {
        char c = s[i];
        if (c < 33 || c > 126 || c == '/') return 0;
    }
    if (strcmp(s, ".") == 0 || strcmp(s, "..") == 0) return 0;
    return 1;
}
static int parse_u32(const char *s, u32 len, u32 *out) {
    u32 v = 0;
    if (len == 0) return -1;
    for (u32 i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        if (v > (0xFFFFFFFFu - 9u) / 10u) return -1;
        v = v * 10u + (u32)(s[i] - '0');
    }
    *out = v; return 0;
}
/* Version compare: -1 if a<b, 0 if equal, 1 if a>b. Components are
   dot-separated integers, missing components count as 0. */
static int version_cmp(const char *a, const char *b) {
    for (int comp = 0; comp < 4; comp++) {
        u32 av = 0, bv = 0;
        const char *pa = a, *pb = b;
        for (int c = 0; c < comp; c++) {
            while (*pa && *pa != '.') pa++;
            if (*pa == '.') pa++;
            while (*pb && *pb != '.') pb++;
            if (*pb == '.') pb++;
        }
        while (*pa >= '0' && *pa <= '9') { av = av * 10u + (u32)(*pa - '0'); pa++; }
        while (*pb >= '0' && *pb <= '9') { bv = bv * 10u + (u32)(*pb - '0'); pb++; }
        if (av < bv) return -1;
        if (av > bv) return 1;
    }
    return 0;
}
/* One dependency token: name, name>=version, or name==version.
   Returns 0 if satisfied by the registry, -1 if missing/conflicting,
   -2 if malformed. */
static int dep_check_token(const char *tok, u32 tok_len) {
    char name[32]; char ver[16]; int op = 0; /* 0 any, 1 >=, 2 == */
    u32 name_len = tok_len, ver_len = 0;
    for (u32 i = 0; i + 1 < tok_len; i++) {
        if (tok[i] == '>' && tok[i+1] == '=') { name_len = i; ver_len = tok_len - i - 2; op = 1; break; }
        if (tok[i] == '=' && tok[i+1] == '=') { name_len = i; ver_len = tok_len - i - 2; op = 2; break; }
        if (tok[i] == '>' || tok[i] == '=') return -2;
    }
    if (name_len == 0 || name_len >= 32 || ver_len >= 16) return -2;
    memset(name, 0, sizeof(name)); memcpy(name, tok, name_len);
    if (!valid_pkg_name(name)) return -2;
    if (op != 0) {
        memset(ver, 0, sizeof(ver)); memcpy(ver, tok + name_len + 2, ver_len);
        if (!valid_version(ver)) return -2;
    }
    for (int i = 0; i < reg_count; i++) {
        if (strcmp(registry[i].name, name) == 0) {
            if (op == 0) return 0;
            int cmp = version_cmp(registry[i].version, ver);
            if (op == 1 && cmp >= 0) return 0;
            if (op == 2 && cmp == 0) return 0;
            return -1; /* conflicting version */
        }
    }
    return -1; /* missing */
}
static int dep_name_of_token(const char *tok, u32 tok_len, char *out32) {
    u32 name_len = tok_len;
    for (u32 i = 0; i + 1 < tok_len; i++) {
        if ((tok[i] == '>' && tok[i+1] == '=') || (tok[i] == '=' && tok[i+1] == '=')) { name_len = i; break; }
    }
    if (name_len == 0 || name_len >= 32) return -1;
    memset(out32, 0, 32); memcpy(out32, tok, name_len); return 0;
}

static int registry_load(void) {
    reg_count = 0;
    if (!fs_mounted()) return -1;
    u8 buf[REG_MAX + 1]; u32 size = 0;
    if (fs_read("packages.txt", buf, REG_MAX, &size) != 0) return 0; /* none installed */
    buf[size] = 0;
    u32 pos = 0;
    while (pos < size && reg_count < PKG_MAX_PKGS) {
        u32 ls = pos;
        while (pos < size && buf[pos] != '\n') pos++;
        u32 ll = pos - ls;
        if (pos < size) pos++;
        if (ll == 0) continue;
        /* name|version|depends|file,hash;file,hash */
        int p1 = -1, p2 = -1, p3 = -1;
        for (u32 i = 0; i < ll; i++) if (buf[ls+i] == '|') {
            if (p1 < 0) p1 = (int)i; else if (p2 < 0) p2 = (int)i; else if (p3 < 0) p3 = (int)i; else break;
        }
        if (p1 <= 0 || p2 <= p1 + 1 || p3 <= p2) { console_write("pkg: skipping malformed registry line\n"); continue; }
        struct reg_pkg *r = &registry[reg_count];
        memset(r, 0, sizeof(*r));
        memcpy(r->name, buf + ls, (u32)p1);
        memcpy(r->version, buf + ls + p1 + 1, (u32)(p2 - p1 - 1));
        memcpy(r->depends, buf + ls + p2 + 1, (u32)(p3 - p2 - 1));
        if (!valid_pkg_name(r->name) || !valid_version(r->version)) { console_write("pkg: skipping malformed registry line\n"); continue; }
        /* Files: split the rest by ';', each "file,hash". */
        u32 fpos = ls + (u32)p3 + 1, fend = ls + ll;
        int nf = 0, bad = 0;
        while (fpos < fend && nf < PKG_MAX_FILES) {
            u32 fs = fpos;
            while (fpos < fend && buf[fpos] != ';') fpos++;
            u32 fl = fpos - fs;
            if (fpos < fend) fpos++;
            int comma = -1;
            for (u32 i = 0; i < fl; i++) if (buf[fs+i] == ',') { comma = (int)i; break; }
            if (comma <= 0 || fl - (u32)comma - 1 != 64) { bad = 1; break; }
            memcpy(r->files[nf], buf + fs, (u32)comma);
            if (!valid_file_name(r->files[nf]) || sha256_parse_hex((const char *)buf + fs + comma + 1, r->hashes[nf]) != 0) { bad = 1; break; }
            nf++;
        }
        if (bad || nf == 0 || fpos != fend) { console_write("pkg: skipping malformed registry line\n"); continue; }
        r->nfiles = nf;
        reg_count++;
    }
    return 0;
}
static int registry_save(void) {
    char out[REG_MAX + 1]; u32 i = 0;
    for (int p = 0; p < reg_count; p++) {
        struct reg_pkg *r = &registry[p];
        const char *s;
        s = r->name; while (*s && i < REG_MAX - 200) out[i++] = *s++;
        if (i < REG_MAX - 200) out[i++] = '|';
        s = r->version; while (*s && i < REG_MAX - 200) out[i++] = *s++;
        if (i < REG_MAX - 200) out[i++] = '|';
        s = r->depends; while (*s && i < REG_MAX - 200) out[i++] = *s++;
        if (i < REG_MAX - 200) out[i++] = '|';
        for (int f = 0; f < r->nfiles; f++) {
            s = r->files[f]; while (*s && i < REG_MAX - 200) out[i++] = *s++;
            if (i < REG_MAX - 200) out[i++] = ',';
            char hex[65]; sha256_hex(r->hashes[f], hex);
            s = hex; while (*s && i < REG_MAX - 200) out[i++] = *s++;
            if (f + 1 < r->nfiles && i < REG_MAX - 200) out[i++] = ';';
        }
        if (i < REG_MAX) out[i++] = '\n';
    }
    return fs_write("packages.txt", (const u8 *)out, i, 0, 0600);
}
static int registry_find(const char *name) {
    for (int i = 0; i < reg_count; i++) if (strcmp(registry[i].name, name) == 0) return i;
    return -1;
}
static int file_in_other_pkg(const char *fname, const char *except_pkg) {
    for (int i = 0; i < reg_count; i++) {
        if (except_pkg && strcmp(registry[i].name, except_pkg) == 0) continue;
        for (int f = 0; f < registry[i].nfiles; f++)
            if (strcmp(registry[i].files[f], fname) == 0) return 1;
    }
    return 0;
}

static int manifest_parse(const u8 *buf, u32 size, struct pkg_manifest *m) {
    memset(m, 0, sizeof(*m));
    if (size < 12 || memcmp(buf, "NXPKG001", 8) != 0) return -1;
    u32 mlen = (u32)buf[8] | ((u32)buf[9] << 8) | ((u32)buf[10] << 16) | ((u32)buf[11] << 24);
    if (mlen == 0 || mlen > 2048 || 12 + mlen > size) return -1;
    const u8 *man = buf + 12;
    if (man[mlen-1] != '\n') return -1;
    for (u32 i = 0; i < mlen; i++) {
        if (man[i] == 0 || (man[i] < 32 && man[i] != '\n') || man[i] > 126) return -1;
    }
    int got_name = 0, got_ver = 0, got_dep = 0;
    u32 pos = 0;
    while (pos < mlen) {
        u32 ls = pos;
        while (pos < mlen && man[pos] != '\n') pos++;
        u32 ll = pos - ls;
        if (pos < mlen) pos++;
        if (ll == 0) return -1;
        if (ll >= 5 && memcmp(man + ls, "name:", 5) == 0) {
            if (got_name) return -1;
            u32 vlen = ll - 5;
            if (vlen >= 32) return -1;
            memcpy(m->name, man + ls + 5, vlen);
            if (!valid_pkg_name(m->name)) return -1;
            got_name = 1;
        } else if (ll >= 8 && memcmp(man + ls, "version:", 8) == 0) {
            if (got_ver) return -1;
            u32 vlen = ll - 8;
            if (vlen >= 16) return -1;
            memcpy(m->version, man + ls + 8, vlen);
            if (!valid_version(m->version)) return -1;
            got_ver = 1;
        } else if (ll >= 8 && memcmp(man + ls, "depends:", 8) == 0) {
            if (got_dep) return -1;
            u32 vlen = ll - 8;
            if (vlen >= 128) return -1;
            memcpy(m->depends, man + ls + 8, vlen);
            got_dep = 1;
        } else if (ll >= 5 && memcmp(man + ls, "file:", 5) == 0) {
            if (m->nfiles >= PKG_MAX_FILES) return -1;
            /* file:<name>:<size>:<hex64> */
            int c1 = -1, c2 = -1;
            for (u32 i = 5; i < ll; i++) if (man[ls+i] == ':') {
                if (c1 < 0) c1 = (int)i; else if (c2 < 0) c2 = (int)i; else break;
            }
            if (c1 <= 5 || c2 <= c1 + 1 || ll - (u32)c2 - 1 != 64) return -1;
            struct pkg_file *f = &m->files[m->nfiles];
            memset(f, 0, sizeof(*f));
            u32 nlen = (u32)c1 - 5;
            if (nlen >= 32) return -1;
            memcpy(f->name, man + ls + 5, nlen);
            if (!valid_file_name(f->name)) return -1;
            for (int j = 0; j < m->nfiles; j++) if (strcmp(m->files[j].name, f->name) == 0) return -1;
            if (parse_u32((const char *)man + ls + c1 + 1, (u32)c2 - (u32)c1 - 1, &f->size) != 0) return -1;
            if (f->size == 0 || f->size > 65536) return -1;
            if (sha256_parse_hex((const char *)man + ls + c2 + 1, f->hash) != 0) return -1;
            m->nfiles++;
        } else return -1; /* unknown line: reject whole manifest */
    }
    if (!got_name || !got_ver || !got_dep || m->nfiles == 0) return -1;
    /* Blob layout must match exactly: no lying sizes, no trailing data. */
    u32 off = 12 + mlen;
    for (int i = 0; i < m->nfiles; i++) {
        m->files[i].blob_off = off;
        if (off > size || m->files[i].size > size - off) return -1;
        off += m->files[i].size;
        /* Hash verification, before anything is written. */
        u8 digest[32];
        sha256_compute(buf + m->files[i].blob_off, m->files[i].size, digest);
        if (memcmp(digest, m->files[i].hash, 32) != 0) return -1;
    }
    if (off != size) return -1;
    return 0;
}

int pkg_list(void) {
    if (registry_load() != 0) { console_write("pkg: no filesystem\n"); return -1; }
    if (reg_count == 0) { console_write("(no packages installed)\n"); return 0; }
    for (int i = 0; i < reg_count; i++) {
        console_printf("%s %s  depends: %s  files: %u\n",
                       registry[i].name, registry[i].version,
                       registry[i].depends[0] ? registry[i].depends : "(none)",
                       registry[i].nfiles);
    }
    return reg_count;
}

int pkg_install(const char *pkgfile) {
    if (!fs_mounted()) { console_write("pkg: no filesystem\n"); return -1; }
    u32 size = 0;
    if (fs_read(pkgfile, pkg_buf, sizeof(pkg_buf), &size) != 0) {
        console_write("pkg: cannot read package file (missing or too large)\n"); return -1;
    }
    struct pkg_manifest m;
    if (manifest_parse(pkg_buf, size, &m) != 0) {
        console_write("pkg: malformed package or hash mismatch, install refused\n"); return -1;
    }
    if (registry_load() != 0) return -1;
    int existing = registry_find(m.name);
    int upgrade = 0;
    if (existing >= 0) {
        if (strcmp(registry[existing].version, m.version) == 0) {
            console_write("pkg: package already installed (same version)\n"); return -1;
        }
        upgrade = 1;
    }
    if (reg_count >= PKG_MAX_PKGS && !upgrade) {
        console_write("pkg: package registry full\n"); return -1;
    }
    /* Dependencies: every dep must be satisfied by the current
       registry. Self-dependency is rejected explicitly, and a
       dependency cycle cannot be created this way: A depending on B
       cannot install until B is already installed, and vice versa. */
    if (m.depends[0]) {
        u32 pos = 0, dlen = strlen(m.depends);
        while (pos < dlen) {
            u32 ds = pos;
            while (pos < dlen && m.depends[pos] != ',') pos++;
            u32 dl = pos - ds;
            if (pos < dlen) pos++;
            if (dl == 0) { console_write("pkg: malformed dependency list\n"); return -1; }
            char depname[32];
            if (dep_name_of_token(m.depends + ds, dl, depname) != 0) { console_write("pkg: malformed dependency\n"); return -1; }
            if (strcmp(depname, m.name) == 0) { console_write("pkg: package depends on itself\n"); return -1; }
            int r = dep_check_token(m.depends + ds, dl);
            if (r == -2) { console_write("pkg: malformed dependency\n"); return -1; }
            if (r != 0) { console_write("pkg: missing or conflicting dependency, install refused\n"); return -1; }
        }
    }
    /* Target files must not belong to another package or be a loose
       file, except files of the package being upgraded. */
    const char *except = upgrade ? m.name : 0;
    for (int i = 0; i < m.nfiles; i++) {
        if (file_in_other_pkg(m.files[i].name, except)) {
            console_write("pkg: file already owned by another package\n"); return -1;
        }
        if (!upgrade && fs_exists(m.files[i].name)) {
            console_write("pkg: file already exists on disk\n"); return -1;
        }
    }
    /* Free-space pre-check (upgrade: new files that are not overwrites). */
    {
        u32 need_sectors = 0;
        for (int i = 0; i < m.nfiles; i++) {
            int is_overwrite = 0;
            if (upgrade) for (int j = 0; j < registry[existing].nfiles; j++)
                if (strcmp(registry[existing].files[j], m.files[i].name) == 0) is_overwrite = 1;
            if (!is_overwrite) need_sectors += (m.files[i].size + 511) / 512;
        }
        if (need_sectors > fs_free_sectors()) { console_write("pkg: not enough disk space\n"); return -1; }
    }
    /* Write files. On failure, roll back files written in this install
       (upgrade rollback cannot restore overwritten old files, so the
       pre-checks above are what keep that path from failing in practice;
       the registry is still the old version in that case, which the
       release notes state as an upgrade atomicity limit). */
    int written = 0;
    for (int i = 0; i < m.nfiles; i++) {
        if (fs_write(m.files[i].name, pkg_buf + m.files[i].blob_off, m.files[i].size, 0, 0644) != 0) {
            console_write("pkg: write failed, rolling back\n");
            for (int j = 0; j < written; j++) {
                int is_old = 0;
                if (upgrade) for (int k = 0; k < registry[existing].nfiles; k++)
                    if (strcmp(registry[existing].files[k], m.files[j].name) == 0) is_old = 1;
                if (!is_old) fs_delete(m.files[j].name);
            }
            return -1;
        }
        written++;
    }
    /* Upgrade: delete old files that the new version dropped. */
    if (upgrade) {
        for (int j = 0; j < registry[existing].nfiles; j++) {
            int kept = 0;
            for (int i = 0; i < m.nfiles; i++) if (strcmp(m.files[i].name, registry[existing].files[j]) == 0) kept = 1;
            if (!kept) fs_delete(registry[existing].files[j]);
        }
    }
    /* Registry last. */
    if (upgrade) {
        struct reg_pkg *r = &registry[existing];
        memset(r, 0, sizeof(*r));
        memcpy(r->name, m.name, strlen(m.name));
        memcpy(r->version, m.version, strlen(m.version));
        memcpy(r->depends, m.depends, strlen(m.depends));
        r->nfiles = m.nfiles;
        for (int i = 0; i < m.nfiles; i++) {
            memcpy(r->files[i], m.files[i].name, strlen(m.files[i].name));
            memcpy(r->hashes[i], m.files[i].hash, 32);
        }
        console_printf("Upgraded %s to %s\n", m.name, m.version);
    } else {
        struct reg_pkg *r = &registry[reg_count];
        memset(r, 0, sizeof(*r));
        memcpy(r->name, m.name, strlen(m.name));
        memcpy(r->version, m.version, strlen(m.version));
        memcpy(r->depends, m.depends, strlen(m.depends));
        r->nfiles = m.nfiles;
        for (int i = 0; i < m.nfiles; i++) {
            memcpy(r->files[i], m.files[i].name, strlen(m.files[i].name));
            memcpy(r->hashes[i], m.files[i].hash, 32);
        }
        reg_count++;
        console_printf("Installed %s %s\n", m.name, m.version);
    }
    if (registry_save() != 0) {
        console_write("pkg: registry write failed\n"); return -1;
    }
    return 0;
}

int pkg_remove(const char *name, int force) {
    if (!valid_pkg_name(name)) { console_write("pkg: bad package name\n"); return -1; }
    if (registry_load() != 0) return -1;
    int idx = registry_find(name);
    if (idx < 0) { console_write("pkg: package not installed\n"); return -1; }
    /* Dependents: refuse unless forced, with a warning naming them. */
    for (int i = 0; i < reg_count; i++) {
        if (i == idx || !registry[i].depends[0]) continue;
        u32 pos = 0, dlen = strlen(registry[i].depends);
        while (pos < dlen) {
            u32 ds = pos;
            while (pos < dlen && registry[i].depends[pos] != ',') pos++;
            u32 dl = pos - ds;
            if (pos < dlen) pos++;
            char depname[32];
            if (dep_name_of_token(registry[i].depends + ds, dl, depname) == 0 &&
                strcmp(depname, name) == 0) {
                if (!force) {
                    console_printf("pkg: %s depends on %s, removal refused (use force to override)\n",
                                   registry[i].name, name);
                    return -1;
                }
                console_printf("pkg: warning: forced removal, %s now has a broken dependency\n", registry[i].name);
            }
        }
    }
    for (int f = 0; f < registry[idx].nfiles; f++)
        if (!fs_exists(registry[idx].files[f])) { console_write("pkg: package file missing, removal aborted\n"); return -1; }
    for (int f = 0; f < registry[idx].nfiles; f++) fs_delete(registry[idx].files[f]);
    for (int i = idx; i + 1 < reg_count; i++) registry[i] = registry[i+1];
    reg_count--;
    if (registry_save() != 0) { console_write("pkg: registry write failed\n"); return -1; }
    console_printf("Removed %s\n", name);
    return 0;
}

int pkg_verify_file(const char *name, const u8 *data, u32 len) {
    if (registry_load() != 0) return 0; /* no registry: loose file, as before */
    for (int i = 0; i < reg_count; i++) {
        for (int f = 0; f < registry[i].nfiles; f++) {
            if (strcmp(registry[i].files[f], name) == 0) {
                u8 digest[32];
                sha256_compute(data, len, digest);
                return memcmp(digest, registry[i].hashes[f], 32) == 0 ? 0 : -1;
            }
        }
    }
    return 0;
}
