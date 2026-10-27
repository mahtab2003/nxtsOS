#include "pkg.h"
#include "sha256.h"
#include "console.h"
#include "../fs/vfs.h"
#include "../net/rsaverify.h"
#include "../net/net.h"
#include "vendor_pubkey.h"

#define PKG_MAX_SIZE 132096
#define PKG_MAX_FILES 8
#define PKG_MAX_PKGS 8
#define REG_MAX 2048

static u8 pkg_buf[PKG_MAX_SIZE];

struct pkg_file { char name[32]; u32 size; u8 hash[32]; u32 blob_off; };
struct pkg_manifest {
    char name[32]; char version[16]; char depends[128];
    struct pkg_file files[PKG_MAX_FILES]; int nfiles;
    u32 mlen;            /* manifest byte length (signed region) */
    u8 sig[256];         /* NXPKG002 RSA signature over the manifest */
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

/* manifest_parse returns 0 on success, -1 on malformed package or
   hash mismatch, -2 on legacy unsigned NXPKG001 (refused with its
   own message: the v1.0 installer requires a signature). */
static int manifest_parse(const u8 *buf, u32 size, struct pkg_manifest *m) {
    memset(m, 0, sizeof(*m));
    if (size < 12) return -1;
    if (memcmp(buf, "NXPKG001", 8) == 0) return -2;
    if (memcmp(buf, "NXPKG002", 8) != 0) return -1;
    u32 mlen = (u32)buf[8] | ((u32)buf[9] << 8) | ((u32)buf[10] << 16) | ((u32)buf[11] << 24);
    if (mlen == 0 || mlen > 2048 || 12 + mlen > size) return -1;
    m->mlen = mlen;
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
    /* Blob layout must match exactly: no lying sizes, and after the
       blobs exactly one signature trailer (NXSG + u16 length +
       256-byte signature), no trailing data. */
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
    if (size - off != 4 + 2 + 256) return -1;
    if (memcmp(buf + off, "NXSG", 4) != 0) return -1;
    u32 sig_len = (u32)buf[off + 4] | ((u32)buf[off + 5] << 8);
    if (sig_len != 256) return -1;
    memcpy(m->sig, buf + off + 6, 256);
    /* size - off == 262 was checked above: trailer is exactly the
       rest of the file, so there is no trailing data. */
    return 0;
}

/* Signature verification for one parsed NXPKG002 package.
   The signature covers the manifest bytes only; the manifest
   carries the per-file SHA-256 hashes, and manifest_parse
   already verified every blob against them, so a valid
   signature authenticates the whole package. Trust anchors,
   tried in order: the compiled-in vendor key, then each
   well-formed line of the root-owned pubkeys.txt keyring
   (one 512-hex-char RSA-2048 modulus per line, exponent
   65537). A missing keyring is not an error. Returns 0 iff
   some anchor verifies. Each RSA verify is a 2048-bit
   modexp (well under a second); a full keyring costs a
   few seconds worst case, acceptable for a root-initiated
   install. */
/* Verify an RSA PKCS#1 v1.5 SHA-256 signature against the trust
   anchors, in order: compiled-in vendor key, then each keyring
   modulus in root-owned pubkeys.txt. Shared by package installs
   and by repository index verification. Returns 0 if any anchor
   verifies, else -1. */
static int pkg_verify_sig(const u8 *msg, u32 msg_len, const u8 *sig) {
    if (rsa_verify_sha256(VENDOR_MOD, 256, VENDOR_EXP,
                          sig, 256, msg, msg_len) == 0) return 0;
    /* Keyring: root-owned pubkeys.txt, one modulus per line. */
    static u8 kr_buf[8192];
    u32 kr_size = 0;
    if (fs_read("pubkeys.txt", kr_buf, sizeof(kr_buf) - 1, &kr_size) != 0) return -1;
    kr_buf[kr_size] = 0;
    u32 pos = 0;
    while (pos < kr_size) {
        u32 ls = pos;
        while (pos < kr_size && kr_buf[pos] != '\n') pos++;
        u32 ll = pos - ls;
        if (pos < kr_size) pos++;
        if (ll == 0) continue;
        if (ll != 512) { console_write("pkg: skipping malformed keyring line\n"); continue; }
        u8 mod[256];
        int bad = 0;
        for (int i = 0; i < 256; i++) {
            char h0 = (char)kr_buf[ls + i * 2], h1 = (char)kr_buf[ls + i * 2 + 1];
            int v0 = (h0 >= '0' && h0 <= '9') ? h0 - '0' :
                     (h0 >= 'a' && h0 <= 'f') ? h0 - 'a' + 10 :
                     (h0 >= 'A' && h0 <= 'F') ? h0 - 'A' + 10 : -1;
            int v1 = (h1 >= '0' && h1 <= '9') ? h1 - '0' :
                     (h1 >= 'a' && h1 <= 'f') ? h1 - 'a' + 10 :
                     (h1 >= 'A' && h1 <= 'F') ? h1 - 'A' + 10 : -1;
            if (v0 < 0 || v1 < 0) { bad = 1; break; }
            mod[i] = (u8)((v0 << 4) | v1);
        }
        if (bad) { console_write("pkg: skipping malformed keyring line\n"); continue; }
        if (rsa_verify_sha256(mod, 256, 65537u,
                              sig, 256, msg, msg_len) == 0) return 0;
    }
    return -1;
}

static int pkg_verify_signature(const u8 *buf, const struct pkg_manifest *m) {
    return pkg_verify_sig(buf + 12, m->mlen, m->sig);
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
    int pr = manifest_parse(pkg_buf, size, &m);
    if (pr == -2) {
        console_write("pkg: package is not signed (legacy format), install refused\n"); return -1;
    }
    if (pr != 0) {
        console_write("pkg: malformed package or hash mismatch, install refused\n"); return -1;
    }
    if (pkg_verify_signature(pkg_buf, &m) != 0) {
        console_write("pkg: bad package signature, install refused\n"); return -1;
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

/* ---------- Phase 11: system update bundles (.nxupd) ---------- */
/* Bundle format: magic "NXUPD001", then NXPKG002 packages back to
   back. Each package inside is already signed, so the bundle needs
   no separate signature: sysupdate verifies every package exactly
   like pkg_install does, BEFORE writing anything (two-phase).
   A snapshot (old file contents + old registry) is taken before
   the commit; any failure restores it. One snapshot generation
   is kept: a successful update leaves it for `sysrollback`, a
   failed update restores it and deletes it (if the restore fully
   succeeds), and `sysrollback` consumes it. */
#define UPD_MAX_BUNDLE 524288
#define UPD_MAX_PKGS 8
#define UPD_MAX_BACKUPS 64
static u8 upd_bundle[UPD_MAX_BUNDLE];
static u8 upd_snap_buf[65536];
static char upd_names[32][32];
static u32 upd_sizes[32];

struct upd_pkg { struct pkg_manifest m; u32 off; u32 len; int old_idx; };
static struct upd_pkg upd_pkgs[UPD_MAX_PKGS];
static int upd_npkgs = 0;
static int upd_order[UPD_MAX_PKGS]; /* commit order (topological) */

/* Length of the NXPKG002 package starting at buf+pos (bundle
   framing only — NOT verification; the copy still goes through
   manifest_parse + signature checks). Returns 0 on bad framing. */
static u32 upd_package_len(const u8 *buf, u32 size, u32 pos) {
    if (size - pos < 12) return 0;
    if (memcmp(buf + pos, "NXPKG002", 8) != 0) return 0;
    u32 mlen = (u32)buf[pos + 8] | ((u32)buf[pos + 9] << 8) |
               ((u32)buf[pos + 10] << 16) | ((u32)buf[pos + 11] << 24);
    if (mlen == 0 || mlen > 2048) return 0;
    if (pos + 12 + mlen > size) return 0;
    const u8 *man = buf + pos + 12;
    if (man[mlen - 1] != '\n') return 0;
    u32 nfiles = 0, sum = 0, p = 0;
    while (p < mlen) {
        u32 ls = p;
        while (p < mlen && man[p] != '\n') p++;
        u32 ll = p - ls;
        if (p < mlen) p++;
        if (ll == 0) return 0;
        if (ll >= 5 && memcmp(man + ls, "file:", 5) == 0) {
            if (nfiles >= PKG_MAX_FILES) return 0;
            int c1 = -1, c2 = -1;
            for (u32 i = 5; i < ll; i++) if (man[ls + i] == ':') {
                if (c1 < 0) c1 = (int)i; else if (c2 < 0) c2 = (int)i; else break;
            }
            if (c1 <= 5 || c2 <= c1 + 1) return 0;
            u32 sz = 0;
            if (parse_u32((const char *)man + ls + c1 + 1, (u32)c2 - (u32)c1 - 1, &sz) != 0) return 0;
            if (sz == 0 || sz > 65536) return 0;
            sum += sz;
            nfiles++;
        }
    }
    if (nfiles == 0) return 0;
    u32 total = 12 + mlen + sum + 262;
    if (pos + total > size) return 0;
    u32 tpos = pos + 12 + mlen + sum;
    if (memcmp(buf + tpos, "NXSG", 4) != 0) return 0;
    u32 slen = (u32)buf[tpos + 4] | ((u32)buf[tpos + 5] << 8);
    if (slen != 256) return 0;
    return total;
}

/* One dependency token against a (name, version) pair.
   Returns 1 if satisfied, 0 if not, -1 if malformed. */
static int upd_token_satisfied(const char *tok, u32 tok_len,
                               const char *name, const char *ver) {
    char dname[32]; char dver[16]; int op = 0;
    u32 name_len = tok_len, ver_len = 0;
    for (u32 i = 0; i + 1 < tok_len; i++) {
        if (tok[i] == '>' && tok[i + 1] == '=') { name_len = i; ver_len = tok_len - i - 2; op = 1; break; }
        if (tok[i] == '=' && tok[i + 1] == '=') { name_len = i; ver_len = tok_len - i - 2; op = 2; break; }
        if (tok[i] == '>' || tok[i] == '=') return -1;
    }
    if (name_len == 0 || name_len >= 32 || ver_len >= 16) return -1;
    memset(dname, 0, sizeof(dname)); memcpy(dname, tok, name_len);
    if (strcmp(dname, name) != 0) return 0; /* token is for another package */
    if (op == 0) return 1;
    memset(dver, 0, sizeof(dver)); memcpy(dver, tok + name_len + 2, ver_len);
    if (!valid_version(dver)) return -1;
    int cmp = version_cmp(ver, dver);
    if (op == 1) return cmp >= 0 ? 1 : 0;
    return cmp == 0 ? 1 : 0;
}

/* Check one package's depends list against the virtual registry:
   installed packages (with bundle packages overriding their old
   versions) + bundle packages. Returns 0 if all satisfied, else -1.
   Self-dependency is refused outright. */
static int upd_check_deps(const struct pkg_manifest *m) {
    if (!m->depends[0]) return 0;
    u32 pos = 0, dlen = strlen(m->depends);
    while (pos < dlen) {
        u32 ds = pos;
        while (pos < dlen && m->depends[pos] != ',') pos++;
        u32 dl = pos - ds;
        if (pos < dlen) pos++;
        if (dl == 0) return -1;
        char depname[32];
        if (dep_name_of_token(m->depends + ds, dl, depname) != 0) return -1;
        if (strcmp(depname, m->name) == 0) return -1; /* self-dependency */
        int ok = 0, bad = 0;
        for (int i = 0; i < reg_count && !ok && !bad; i++) {
            /* Skip installed packages the bundle replaces: their new
               version is what counts. */
            int replaced = 0;
            for (int j = 0; j < upd_npkgs; j++)
                if (strcmp(registry[i].name, upd_pkgs[j].m.name) == 0) replaced = 1;
            if (replaced) continue;
            int r = upd_token_satisfied(m->depends + ds, dl, registry[i].name, registry[i].version);
            if (r < 0) bad = 1; else if (r == 1) ok = 1;
        }
        for (int j = 0; j < upd_npkgs && !ok && !bad; j++) {
            int r = upd_token_satisfied(m->depends + ds, dl, upd_pkgs[j].m.name, upd_pkgs[j].m.version);
            if (r < 0) bad = 1; else if (r == 1) ok = 1;
        }
        if (bad || !ok) return -1;
    }
    return 0;
}

/* ---------- Snapshot / rollback ---------- */
struct snap_entry { char orig[32]; char backup[8]; };
static struct snap_entry snap_entries[UPD_MAX_BACKUPS];
static int snap_count = 0;
static int snap_reg_existed = 0;
static u8 snap_reg[REG_MAX + 1];
static u32 snap_reg_size = 0;

static int snap_have(const char *orig) {
    for (int i = 0; i < snap_count; i++)
        if (strcmp(snap_entries[i].orig, orig) == 0) return 1;
    return 0;
}

/* Delete a previous snapshot's files, using ITS journal as the
   list (never blind-delete rb* names: those could be user files
   if no snapshot journal exists). Returns 0 even if nothing
   existed. */
static void snap_delete_old(void) {
    u8 jb[8192]; u32 jsize = 0;
    if (fs_read("rollback.txt", jb, sizeof(jb) - 1, &jsize) != 0) {
        fs_delete("rollback.txt"); fs_delete("rb_packages.txt");
        return;
    }
    jb[jsize] = 0;
    u32 pos = 0;
    while (pos < jsize) {
        u32 ls = pos;
        while (pos < jsize && jb[pos] != '\n') pos++;
        u32 ll = pos - ls;
        if (pos < jsize) pos++;
        if (ll > 2 && jb[ls] == 'F' && jb[ls + 1] == '|') {
            /* F|orig|backup */
            int p1 = -1;
            for (u32 i = 2; i < ll; i++) if (jb[ls + i] == '|') { p1 = (int)i; break; }
            if (p1 > 0) {
                char bk[8]; u32 bl = ll - (u32)p1 - 1;
                if (bl < sizeof(bk)) { memcpy(bk, jb + ls + p1 + 1, bl); bk[bl] = 0; fs_delete(bk); }
            }
        }
    }
    fs_delete("rollback.txt");
    fs_delete("rb_packages.txt");
}

/* Take the snapshot for the verified bundle. Backs up every file
   the update could overwrite or drop (old versions' files + any
   target file that already exists), records files the update will
   newly create as D entries, and copies the registry. On any
   failure, deletes what it wrote and returns -1 (nothing else
   has been touched yet, so there is nothing to restore). */
static int snap_take(void) {
    snap_count = 0;
    snap_delete_old();
    /* Collect the backup set (deduplicated by original name). */
    for (int i = 0; i < upd_npkgs; i++) {
        struct upd_pkg *up = &upd_pkgs[i];
        if (up->old_idx >= 0) {
            struct reg_pkg *r = &registry[up->old_idx];
            for (int f = 0; f < r->nfiles; f++) {
                if (snap_count >= UPD_MAX_BACKUPS) return -1;
                if (!snap_have(r->files[f])) {
                    memset(&snap_entries[snap_count], 0, sizeof(struct snap_entry));
                    memcpy(snap_entries[snap_count].orig, r->files[f], strlen(r->files[f]));
                    snap_count++;
                }
            }
        }
        for (int f = 0; f < up->m.nfiles; f++) {
            if (fs_exists(up->m.files[f].name) && !snap_have(up->m.files[f].name)) {
                if (snap_count >= UPD_MAX_BACKUPS) return -1;
                memset(&snap_entries[snap_count], 0, sizeof(struct snap_entry));
                memcpy(snap_entries[snap_count].orig, up->m.files[f].name, strlen(up->m.files[f].name));
                snap_count++;
            }
        }
    }
    /* Directory-slot check: current + backups + journal + registry
       copy + temp files + newly created files must fit in 32. */
    int cur = fs_enum_as(0, upd_names, upd_sizes, 32);
    if (cur < 0) return -1;
    int newfiles = 0;
    for (int i = 0; i < upd_npkgs; i++)
        for (int f = 0; f < upd_pkgs[i].m.nfiles; f++)
            if (!fs_exists(upd_pkgs[i].m.files[f].name)) newfiles++;
    if (cur + snap_count + 2 + upd_npkgs + newfiles > 32) {
        console_write("sysupdate: not enough directory space for update + snapshot\n");
        return -1;
    }
    /* Write backups. */
    for (int i = 0; i < snap_count; i++) {
        char bk[8];
        bk[0] = 'r'; bk[1] = 'b';
        bk[2] = (char)('0' + (i / 10)); bk[3] = (char)('0' + (i % 10)); bk[4] = 0;
        memcpy(snap_entries[i].backup, bk, 5);
        u32 sz = 0;
        if (fs_read(snap_entries[i].orig, upd_snap_buf, sizeof(upd_snap_buf), &sz) != 0) goto fail;
        if (fs_write(bk, upd_snap_buf, sz, 0, 0600) != 0) goto fail;
    }
    /* Registry copy. */
    snap_reg_existed = 0; snap_reg_size = 0;
    if (fs_read("packages.txt", snap_reg, REG_MAX, &snap_reg_size) == 0) {
        snap_reg_existed = 1;
        if (fs_write("rb_packages.txt", snap_reg, snap_reg_size, 0, 0600) != 0) goto fail;
    }
    /* Journal: reg flag, F entries (existed), D entries (new). */
    {
        char jb[8192]; u32 ji = 0;
        jb[ji++] = 'r'; jb[ji++] = 'e'; jb[ji++] = 'g'; jb[ji++] = ':';
        jb[ji++] = snap_reg_existed ? '1' : '0'; jb[ji++] = '\n';
        for (int i = 0; i < snap_count; i++) {
            const char *s;
            if (ji > sizeof(jb) - 80) goto fail;
            jb[ji++] = 'F'; jb[ji++] = '|';
            s = snap_entries[i].orig; while (*s) jb[ji++] = *s++;
            jb[ji++] = '|';
            s = snap_entries[i].backup; while (*s) jb[ji++] = *s++;
            jb[ji++] = '\n';
        }
        for (int i = 0; i < upd_npkgs; i++)
            for (int f = 0; f < upd_pkgs[i].m.nfiles; f++)
                if (!snap_have(upd_pkgs[i].m.files[f].name)) {
                    const char *s;
                    if (ji > sizeof(jb) - 80) goto fail;
                    jb[ji++] = 'D'; jb[ji++] = '|';
                    s = upd_pkgs[i].m.files[f].name; while (*s) jb[ji++] = *s++;
                    jb[ji++] = '\n';
                }
        if (fs_write("rollback.txt", (const u8 *)jb, ji, 0, 0600) != 0) goto fail;
    }
    return 0;
fail:
    for (int i = 0; i < snap_count; i++) if (snap_entries[i].backup[0]) fs_delete(snap_entries[i].backup);
    fs_delete("rollback.txt"); fs_delete("rb_packages.txt");
    snap_count = 0;
    return -1;
}

/* Restore the snapshot. Returns 0 iff every entry restored; on
   partial failure the snapshot is left in place so sysrollback
   can be retried. Does not delete the snapshot itself. */
static int snap_restore(void) {
    u8 jb[8192]; u32 jsize = 0;
    if (fs_read("rollback.txt", jb, sizeof(jb) - 1, &jsize) != 0) {
        console_write("sysrollback: no update snapshot found\n"); return -1;
    }
    jb[jsize] = 0;
    int reg_flag = -1, ok = 1;
    u32 pos = 0;
    while (pos < jsize) {
        u32 ls = pos;
        while (pos < jsize && jb[pos] != '\n') pos++;
        u32 ll = pos - ls;
        if (pos < jsize) pos++;
        if (ll == 0) continue;
        if (ll == 5 && memcmp(jb + ls, "reg:1", 5) == 0) { reg_flag = 1; continue; }
        if (ll == 5 && memcmp(jb + ls, "reg:0", 5) == 0) { reg_flag = 0; continue; }
        if (ll > 2 && jb[ls] == 'F' && jb[ls + 1] == '|') {
            int p1 = -1;
            for (u32 i = 2; i < ll; i++) if (jb[ls + i] == '|') { p1 = (int)i; break; }
            if (p1 <= 0) { ok = 0; continue; }
            char orig[32], bk[8];
            u32 ol = (u32)p1 - 2, bl = ll - (u32)p1 - 1;
            if (ol >= 32 || bl >= 8) { ok = 0; continue; }
            memcpy(orig, jb + ls + 2, ol); orig[ol] = 0;
            memcpy(bk, jb + ls + p1 + 1, bl); bk[bl] = 0;
            u32 sz = 0;
            if (fs_read(bk, upd_snap_buf, sizeof(upd_snap_buf), &sz) != 0) { ok = 0; continue; }
            if (fs_write(orig, upd_snap_buf, sz, 0, 0644) != 0) ok = 0;
        } else if (ll > 2 && jb[ls] == 'D' && jb[ls + 1] == '|') {
            char orig[32]; u32 ol = ll - 2;
            if (ol >= 32) { ok = 0; continue; }
            memcpy(orig, jb + ls + 2, ol); orig[ol] = 0;
            if (fs_exists(orig)) fs_delete(orig);
        } else { ok = 0; }
    }
    if (reg_flag == 1) {
        u32 sz = 0;
        if (fs_read("rb_packages.txt", snap_reg, REG_MAX, &sz) != 0) ok = 0;
        else if (fs_write("packages.txt", snap_reg, sz, 0, 0600) != 0) ok = 0;
    } else if (reg_flag == 0) {
        if (fs_exists("packages.txt")) fs_delete("packages.txt");
    } else ok = 0;
    return ok ? 0 : -1;
}

/* Delete the snapshot files listed in its journal. Used after a
   fully successful restore (consumed) and before a new snapshot. */
static void snap_consume(void) {
    snap_delete_old();
}

int pkg_sysupdate(const char *bundlefile) {
    if (!fs_mounted()) { console_write("sysupdate: no filesystem\n"); return -1; }
    u32 bsize = 0;
    if (fs_read(bundlefile, upd_bundle, sizeof(upd_bundle), &bsize) != 0) {
        console_write("sysupdate: cannot read update bundle (missing or too large)\n"); return -1;
    }
    if (bsize < 8 || memcmp(upd_bundle, "NXUPD001", 8) != 0) {
        console_write("sysupdate: not an update bundle\n"); return -1;
    }
    if (registry_load() != 0) return -1;
    /* Phase 1a: walk + verify every package (parse + signature). */
    upd_npkgs = 0;
    u32 pos = 8;
    while (pos < bsize) {
        if (upd_npkgs >= UPD_MAX_PKGS) {
            console_write("sysupdate: too many packages in bundle\n"); return -1;
        }
        u32 len = upd_package_len(upd_bundle, bsize, pos);
        if (len == 0 || len > PKG_MAX_SIZE) {
            console_write("sysupdate: malformed package in bundle, update refused\n"); return -1;
        }
        memcpy(pkg_buf, upd_bundle + pos, len);
        struct upd_pkg *up = &upd_pkgs[upd_npkgs];
        memset(up, 0, sizeof(*up));
        if (manifest_parse(pkg_buf, len, &up->m) != 0) {
            console_write("sysupdate: malformed package or hash mismatch, update refused\n"); return -1;
        }
        if (pkg_verify_signature(pkg_buf, &up->m) != 0) {
            console_write("sysupdate: bad package signature, update refused\n"); return -1;
        }
        up->off = pos; up->len = len;
        up->old_idx = registry_find(up->m.name);
        upd_npkgs++;
        pos += len;
    }
    if (upd_npkgs == 0) { console_write("sysupdate: empty update bundle\n"); return -1; }
    /* Phase 1b: duplicates, same-version, deps (incl. reverse deps
       of installed packages the bundle does not touch), file
       conflicts, duplicate targets. No writes have happened. */
    for (int i = 0; i < upd_npkgs; i++) {
        for (int j = i + 1; j < upd_npkgs; j++)
            if (strcmp(upd_pkgs[i].m.name, upd_pkgs[j].m.name) == 0) {
                console_write("sysupdate: duplicate package in bundle, update refused\n"); return -1;
            }
        if (upd_pkgs[i].old_idx >= 0 &&
            strcmp(registry[upd_pkgs[i].old_idx].version, upd_pkgs[i].m.version) == 0) {
            console_write("sysupdate: package already installed (same version), update refused\n"); return -1;
        }
        if (upd_check_deps(&upd_pkgs[i].m) != 0) {
            console_write("sysupdate: missing or conflicting dependency, update refused\n"); return -1;
        }
    }
    /* Commit order: topological sort over bundle-internal
       dependencies (a package's bundle deps must commit first).
       pkg_install checks dependencies against the live registry,
       so committing in bundle order would fail whenever a later
       bundle package satisfies an earlier one's dependency (the
       bundle_good test puts greet first on purpose). A bundle
       whose dependencies form a cycle has no valid order and is
       refused here — single installs can never create a cycle
       (the first of the pair always fails on a missing dep),
       so bundles must not introduce one either. */
    {
        int done[UPD_MAX_PKGS]; int nordered = 0;
        for (int i = 0; i < UPD_MAX_PKGS; i++) done[i] = 0;
        while (nordered < upd_npkgs) {
            int progress = 0;
            for (int i = 0; i < upd_npkgs; i++) {
                if (done[i]) continue;
                int ready = 1;
                const char *deps = upd_pkgs[i].m.depends;
                if (deps[0]) {
                    u32 p2 = 0, dl2 = strlen(deps);
                    while (p2 < dl2 && ready) {
                        u32 ds = p2;
                        while (p2 < dl2 && deps[p2] != ',') p2++;
                        u32 tl = p2 - ds;
                        if (p2 < dl2) p2++;
                        if (tl == 0) { ready = 0; break; }
                        char dn[32];
                        if (dep_name_of_token(deps + ds, tl, dn) != 0) { ready = 0; break; }
                        for (int j = 0; j < upd_npkgs; j++) {
                            if (j != i && strcmp(dn, upd_pkgs[j].m.name) == 0 && !done[j])
                                ready = 0;
                        }
                    }
                }
                if (ready) { upd_order[nordered++] = i; done[i] = 1; progress = 1; }
            }
            if (!progress) {
                console_write("sysupdate: dependency cycle in bundle, update refused\n");
                return -1;
            }
        }
    }
    /* Reverse deps: installed packages outside the bundle must
       stay satisfied after the update. */
    for (int i = 0; i < reg_count; i++) {
        int in_bundle = 0;
        for (int j = 0; j < upd_npkgs; j++)
            if (strcmp(registry[i].name, upd_pkgs[j].m.name) == 0) in_bundle = 1;
        if (in_bundle || !registry[i].depends[0]) continue;
        u32 p2 = 0, dl2 = strlen(registry[i].depends);
        while (p2 < dl2) {
            u32 ds = p2;
            while (p2 < dl2 && registry[i].depends[p2] != ',') p2++;
            u32 tl = p2 - ds;
            if (p2 < dl2) p2++;
            if (tl == 0) { console_write("sysupdate: malformed installed dependency, update refused\n"); return -1; }
            int ok = 0, bad = 0;
            for (int k = 0; k < reg_count && !ok && !bad; k++) {
                int replaced = 0;
                for (int j = 0; j < upd_npkgs; j++)
                    if (strcmp(registry[k].name, upd_pkgs[j].m.name) == 0) replaced = 1;
                if (replaced) continue;
                int r = upd_token_satisfied(registry[i].depends + ds, tl, registry[k].name, registry[k].version);
                if (r < 0) bad = 1; else if (r == 1) ok = 1;
            }
            for (int j = 0; j < upd_npkgs && !ok && !bad; j++) {
                int r = upd_token_satisfied(registry[i].depends + ds, tl, upd_pkgs[j].m.name, upd_pkgs[j].m.version);
                if (r < 0) bad = 1; else if (r == 1) ok = 1;
            }
            if (bad || !ok) {
                console_printf("sysupdate: update would break dependency of %s, update refused\n", registry[i].name);
                return -1;
            }
        }
    }
    for (int i = 0; i < upd_npkgs; i++) {
        for (int f = 0; f < upd_pkgs[i].m.nfiles; f++) {
            const char *fn = upd_pkgs[i].m.files[f].name;
            for (int j = 0; j < upd_npkgs; j++) {
                if (j == i) continue;
                for (int g = 0; g < upd_pkgs[j].m.nfiles; g++)
                    if (strcmp(fn, upd_pkgs[j].m.files[g].name) == 0) {
                        console_write("sysupdate: two packages claim the same file, update refused\n"); return -1;
                    }
            }
            int owner = -1;
            for (int k = 0; k < reg_count; k++)
                for (int g = 0; g < registry[k].nfiles; g++)
                    if (strcmp(fn, registry[k].files[g]) == 0) owner = k;
            if (owner >= 0) {
                int owner_in_bundle = 0;
                for (int j = 0; j < upd_npkgs; j++)
                    if (strcmp(registry[owner].name, upd_pkgs[j].m.name) == 0) owner_in_bundle = 1;
                /* Owned by the package being upgraded: fine. Owned
                   by another bundle package: already refused above
                   as a duplicate target. Owned by anyone else: no. */
                if (!owner_in_bundle) {
                    console_write("sysupdate: file already owned by another package, update refused\n"); return -1;
                }
                if (owner != upd_pkgs[i].old_idx) {
                    console_write("sysupdate: file already owned by another package, update refused\n"); return -1;
                }
            } else if (fs_exists(fn)) {
                console_write("sysupdate: file already exists on disk, update refused\n"); return -1;
            }
        }
    }
    /* Snapshot, then free-space check for the new files. */
    if (snap_take() != 0) {
        console_write("sysupdate: snapshot failed, update refused\n"); return -1;
    }
    {
        u32 need = 0;
        for (int i = 0; i < upd_npkgs; i++)
            for (int f = 0; f < upd_pkgs[i].m.nfiles; f++)
                if (!snap_have(upd_pkgs[i].m.files[f].name))
                    need += (upd_pkgs[i].m.files[f].size + 511) / 512;
        if (need > fs_free_sectors()) {
            console_write("sysupdate: not enough disk space, update refused\n");
            snap_consume();
            return -1;
        }
    }
    /* Phase 2: commit in topological order via temp files + the
       existing installer. Any failure restores the snapshot. */
    for (int step = 0; step < upd_npkgs; step++) {
        int i = upd_order[step];
        char tmp[16];
        tmp[0] = 'u'; tmp[1] = 'p'; tmp[2] = 'd';
        tmp[3] = (char)('0' + step); tmp[4] = 0;
        memcpy(tmp + 4, ".nxpkg", 7);
        if (fs_exists(tmp)) {
            console_write("sysupdate: temporary file collision, update refused\n");
            goto restore;
        }
        if (fs_write(tmp, upd_bundle + upd_pkgs[i].off, upd_pkgs[i].len, 0, 0644) != 0) {
            console_write("sysupdate: temporary file write failed\n");
            fs_delete(tmp);
            goto restore;
        }
        int r = pkg_install(tmp);
        fs_delete(tmp);
        if (r != 0) {
            console_write("sysupdate: install failed, rolling back\n");
            goto restore;
        }
    }
    console_printf("System update complete: %d package(s), rollback available (sysrollback)\n", upd_npkgs);
    return 0;
restore:
    if (snap_restore() == 0) {
        snap_consume();
        console_write("sysupdate: rolled back to the previous version\n");
    } else {
        console_write("sysupdate: WARNING: rollback incomplete, run sysrollback to retry\n");
    }
    return -1;
}

int pkg_sysrollback(void) {
    if (!fs_mounted()) { console_write("sysrollback: no filesystem\n"); return -1; }
    if (!fs_exists("rollback.txt")) {
        console_write("sysrollback: no update to roll back\n"); return -1;
    }
    if (snap_restore() != 0) {
        console_write("sysrollback: rollback incomplete, snapshot kept, try again\n");
        return -1;
    }
    snap_consume();
    console_write("Rolled back to the previous version\n");
    return 0;
}

/* ---------- Phase 11: remote package repository ---------- */
/* apt-style, but with nxtsOS trust rules. Transport is plain
   HTTP BY DESIGN: the kernel TLS client has no public CA
   trust store (TOFU self-signed roots only), so HTTPS to a
   public host cannot verify anything. Authenticity comes
   from signatures, not transport: the index is RSA-signed
   (vendor key or keyring, same anchors as packages) and
   every package is signature- + hash-checked before
   install — exactly like apt's signed Release files.
   A tampered index, a tampered package, or a 404 page
   all fail structural/signature checks (fail-closed).
   Index format (text):
     NXREPO1
     version:<decimal, publisher-managed, monotonic>
     name|version|file|sha256hex
   Anti-rollback: `pkg update` refuses an index older
   than the stored one. The stored index is re-verified
   on every use, so tampering with it on disk buys
   nothing (and a corrupt stored index is simply
   replaced by the next verified update). */
#define REPO_MAX_INDEX 16384
#define REPO_MAX_ENTRIES 64
struct repo_entry { char name[32]; char version[16]; char file[32]; u8 hash[32]; };
/* Entry tables are file-scope, NOT stack: one table is 64*112 =
   7168 bytes and the kernel stack is only 16 KiB. Declaring
   them as locals in pkg_repo_update overflowed the stack
   (frame ~15 KiB + net_http_get's frame), corrupting adjacent
   memory — that was the "sig fetch fails + hex fragments on
   the console" bug, not a network bug at all. */
static struct repo_entry repo_entries[REPO_MAX_ENTRIES];
static struct repo_entry repo_old_entries[REPO_MAX_ENTRIES];
static char repo_idx[REPO_MAX_INDEX];
/* Signature fetch buffer must hold headers + the 512-byte body:
   net_http_get counts the raw stream (headers included) against
   the buffer, so 600 bytes truncated it and every update failed
   at the signature step. 2048 leaves ample room. */
static char repo_sig_txt[2048];

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int repo_parse_index(const char *buf, u32 len, u32 *version_out,
                            struct repo_entry *entries, int max_entries) {
    if (len < 8 || memcmp(buf, "NXREPO1", 7) != 0) return -1;
    u32 pos = 0;
    int n = 0;
    /* Line 1: NXREPO1 */
    while (pos < len && buf[pos] != '\n') pos++;
    if (pos >= len) return -1;
    pos++;
    /* Line 2: version:<decimal> */
    if (len - pos < 8 || memcmp(buf + pos, "version:", 8) != 0) return -1;
    pos += 8;
    u32 ver = 0, digits = 0;
    while (pos < len && buf[pos] >= '0' && buf[pos] <= '9') {
        /* Overflow is a refusal, not a wrap: a wrapped version
           would confuse the anti-rollback comparison. (The index
           is signature-verified before parsing, so this is
           defense in depth for a signed-but-huge version, not a
           bypass — but a wrap must never silently become a
           small version.) */
        u32 d = (u32)(buf[pos] - '0');
        if (ver > (0xFFFFFFFFu - d) / 10u) return -1;
        ver = ver * 10 + d;
        pos++; digits++;
    }
    if (digits == 0 || pos >= len || buf[pos] != '\n') return -1;
    pos++;
    if (version_out) *version_out = ver;
    while (pos < len) {
        u32 ls = pos;
        while (pos < len && buf[pos] != '\n') pos++;
        u32 ll = pos - ls;
        if (pos < len) pos++;
        if (ll == 0) continue;
        if (n >= max_entries) return -1;
        /* name|version|file|hex64 */
        int p1 = -1, p2 = -1, p3 = -1;
        for (u32 i = 0; i < ll; i++) if (buf[ls + i] == '|') {
            if (p1 < 0) p1 = (int)i; else if (p2 < 0) p2 = (int)i; else if (p3 < 0) p3 = (int)i; else break;
        }
        if (p1 <= 0 || p2 <= p1 + 1 || p3 <= p2 + 1) return -1;
        if (ll - (u32)p3 - 1 != 64) return -1;
        struct repo_entry *e = &entries[n];
        memset(e, 0, sizeof(*e));
        u32 nl = (u32)p1, vl = (u32)p2 - (u32)p1 - 1, fl = (u32)p3 - (u32)p2 - 1;
        if (nl >= 32 || vl >= 16 || fl >= 32) return -1;
        memcpy(e->name, buf + ls, nl);
        memcpy(e->version, buf + ls + p1 + 1, vl);
        memcpy(e->file, buf + ls + p2 + 1, fl);
        if (!valid_pkg_name(e->name) || !valid_version(e->version)) return -1;
        /* Server file: single path segment, must end .nxpkg. */
        if (fl < 7 || strcmp(e->file + fl - 6, ".nxpkg") != 0) return -1;
        for (u32 i = 0; i < fl; i++) {
            char c = e->file[i];
            if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') &&
                !(c >= '0' && c <= '9') && c != '.' && c != '_' && c != '-') return -1;
        }
        {
            int dots = 0;
            for (u32 i = 0; i < fl; i++) {
                if (e->file[i] == '.') { dots++; if (dots >= 2) return -1; }
                else dots = 0;
            }
        }
        for (int i = 0; i < 32; i++) {
            int v0 = hex_val(buf[ls + p3 + 1 + i * 2]);
            int v1 = hex_val(buf[ls + p3 + 1 + i * 2 + 1]);
            if (v0 < 0 || v1 < 0) return -1;
            e->hash[i] = (u8)((v0 << 4) | v1);
        }
        for (int j = 0; j < n; j++)
            if (strcmp(entries[j].name, e->name) == 0) return -1; /* duplicate name */
        n++;
    }
    return n;
}

/* Parse "host[:port][/prefix]" into parts. Host: alnum, '.', '-'.
   Port defaults to 80. Prefix defaults to "". */
static int repo_parse_url(const char *url, char *host, u32 host_max,
                          u16 *port_out, char *prefix, u32 prefix_max) {
    u32 i = 0, hl = 0;
    while (url[i] && url[i] != ':' && url[i] != '/') {
        char c = url[i];
        if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') &&
            !(c >= '0' && c <= '9') && c != '.' && c != '-') return -1;
        if (hl + 1 >= host_max) return -1;
        host[hl++] = c; i++;
    }
    if (hl == 0) return -1;
    host[hl] = 0;
    u16 port = 80;
    if (url[i] == ':') {
        i++;
        u32 v = 0, digits = 0;
        while (url[i] >= '0' && url[i] <= '9') {
            /* Same rule as the index version: overflow refuses
               instead of wrapping into a valid-looking port. */
            u32 d = (u32)(url[i] - '0');
            if (v > (0xFFFFFFFFu - d) / 10u) return -1;
            v = v * 10 + d;
            i++; digits++;
        }
        if (digits == 0 || v < 1 || v > 65535) return -1;
        port = (u16)v;
    }
    if (port_out) *port_out = port;
    u32 pl = 0;
    if (url[i] == '/') {
        i++; /* prefix stored WITHOUT the leading slash: joins
                build "/"+prefix+"/"+file with no double slash */
        while (url[i]) {
            if (url[i] == ' ') return -1;
            if (pl + 1 >= prefix_max) return -1;
            prefix[pl++] = url[i++];
        }
    }
    prefix[pl] = 0;
    return 0;
}

static int repo_read_config(char *url, u32 url_max) {
    u32 sz = 0;
    if (fs_read("repo.txt", (u8 *)url, url_max - 1, &sz) != 0) return -1;
    url[sz] = 0;
    while (sz > 0 && (url[sz - 1] == '\n' || url[sz - 1] == '\r')) url[--sz] = 0;
    return sz > 0 ? 0 : -1;
}

/* Load + re-verify the stored index. Returns entry count or -1. */
static int repo_load_stored(u32 *version_out, struct repo_entry *entries, int max_entries) {
    u32 sz = 0;
    if (fs_read("repo_index.txt", (u8 *)repo_idx, sizeof(repo_idx) - 1, &sz) != 0) return -1;
    repo_idx[sz] = 0;
    u32 ssz = 0;
    if (fs_read("repo_index.sig", (u8 *)repo_sig_txt, sizeof(repo_sig_txt) - 1, &ssz) != 0) return -1;
    if (ssz < 512) return -1;
    u8 sig[256];
    for (int i = 0; i < 256; i++) {
        int v0 = hex_val(repo_sig_txt[i * 2]), v1 = hex_val(repo_sig_txt[i * 2 + 1]);
        if (v0 < 0 || v1 < 0) return -1;
        sig[i] = (u8)((v0 << 4) | v1);
    }
    if (pkg_verify_sig((const u8 *)repo_idx, sz, sig) != 0) return -1;
    return repo_parse_index(repo_idx, sz, version_out, entries, max_entries);
}

static int repo_find(const char *name, struct repo_entry *out) {
    u32 ver = 0;
    int n = repo_load_stored(&ver, repo_entries, REPO_MAX_ENTRIES);
    if (n < 0) return -1;
    for (int i = 0; i < n; i++)
        if (strcmp(repo_entries[i].name, name) == 0) { *out = repo_entries[i]; return 0; }
    return -1;
}

/* Fetch + verify one repo file into pkg_buf. Returns length or -1.
   Checks: HTTP fetch ok + not truncated, index hash match (for
   packages), manifest parse ok, package signature ok. */
static int repo_download(const char *host, u16 port, const char *path,
                         const struct repo_entry *entry) {
    int bl = net_http_get(host, port, path, (char *)pkg_buf, sizeof(pkg_buf));
    if (bl < 0) { console_write("repo: download failed\n"); return -1; }
    if (net_fetch_truncated()) {
        console_write("repo: download truncated, refused\n"); return -1;
    }
    if (entry) {
        u8 digest[32];
        sha256_compute(pkg_buf, (u32)bl, digest);
        if (memcmp(digest, entry->hash, 32) != 0) {
            /* Length printed: a short download (truncated stream)
               and a full-length corruption look identical in the
               hash, but need different fixes. */
            console_printf("repo: package hash does not match index, refused (%d bytes)\n", bl);
            return -1;
        }
    }
    struct pkg_manifest m;
    int pr = manifest_parse(pkg_buf, (u32)bl, &m);
    if (pr == -2) { console_write("repo: package is not signed (legacy format), refused\n"); return -1; }
    if (pr != 0) { console_write("repo: malformed package or hash mismatch, refused\n"); return -1; }
    if (pkg_verify_signature(pkg_buf, &m) != 0) {
        console_write("repo: bad package signature, refused\n"); return -1;
    }
    return bl;
}

int pkg_repo_show(void) {
    char url[128];
    if (repo_read_config(url, sizeof(url)) != 0) {
        console_write("(no repository set)\n"); return 0;
    }
    console_printf("Repository: %s\n", url);
    return 0;
}

int pkg_repo_set(const char *url) {
    if (!fs_mounted()) { console_write("pkg: no filesystem\n"); return -1; }
    if (!url || !url[0]) { console_write("Usage: pkg repo <host[:port][/prefix]>\n"); return -1; }
    if (strlen(url) >= 128) { console_write("pkg repo: URL too long\n"); return -1; }
    char host[64], prefix[64]; u16 port = 80;
    if (repo_parse_url(url, host, sizeof(host), &port, prefix, sizeof(prefix)) != 0) {
        console_write("pkg repo: malformed repository URL\n"); return -1;
    }
    if (fs_write("repo.txt", (const u8 *)url, strlen(url), 0, 0600) != 0) {
        console_write("pkg repo: cannot save repository\n"); return -1;
    }
    console_printf("Repository set to %s\n", url);
    return 0;
}

int pkg_repo_update(void) {
    if (!fs_mounted()) { console_write("pkg: no filesystem\n"); return -1; }
    char url[128];
    if (repo_read_config(url, sizeof(url)) != 0) {
        console_write("pkg update: no repository set (pkg repo <host[:port][/prefix]> first)\n"); return -1;
    }
    char host[64], prefix[64]; u16 port = 80;
    if (repo_parse_url(url, host, sizeof(host), &port, prefix, sizeof(prefix)) != 0) {
        console_write("pkg update: stored repository URL is malformed\n"); return -1;
    }
    /* Stored version FIRST: repo_load_stored reuses repo_idx /
       repo_sig_txt, so it must run before the new index is
       fetched into those buffers (otherwise the anti-rollback
       check would overwrite the new index and the store step
       would write the old one back). */
    u32 old_ver = 0;
    int old_ok = repo_load_stored(&old_ver, repo_old_entries, REPO_MAX_ENTRIES) >= 0;
    char path[128];
    {
        /* Join prefix + filename, no double slash. */
        u32 pl = strlen(prefix);
        while (pl > 0 && prefix[pl - 1] == '/') pl--;
        u32 pi = 0;
        path[pi++] = '/';
        for (u32 i = 0; i < pl; i++) path[pi++] = prefix[i];
        const char *fn = "index.txt";
        if (pl > 0) path[pi++] = '/';
        while (*fn) path[pi++] = *fn++;
        path[pi] = 0;
    }
    int ilen = net_http_get(host, port, path, repo_idx, sizeof(repo_idx) - 1);
    if (ilen < 0 || net_fetch_truncated()) {
        console_write("pkg update: cannot fetch repository index\n"); return -1;
    }
    repo_idx[ilen] = 0;
    /* Fetch the signature (same path, .sig suffix). */
    {
        u32 pl = strlen(path);
        if (pl + 4 >= sizeof(path)) { console_write("pkg update: path too long\n"); return -1; }
        path[pl++] = '.'; path[pl++] = 's'; path[pl++] = 'i'; path[pl++] = 'g'; path[pl] = 0;
    }
    int slen = net_http_get(host, port, path, repo_sig_txt, sizeof(repo_sig_txt) - 1);
    if (slen < 512 || net_fetch_truncated()) {
        console_write("pkg update: cannot fetch repository index signature\n"); return -1;
    }
    u8 sig[256];
    for (int i = 0; i < 256; i++) {
        int v0 = hex_val(repo_sig_txt[i * 2]), v1 = hex_val(repo_sig_txt[i * 2 + 1]);
        if (v0 < 0 || v1 < 0) {
            console_write("pkg update: malformed index signature\n"); return -1;
        }
        sig[i] = (u8)((v0 << 4) | v1);
    }
    if (pkg_verify_sig((const u8 *)repo_idx, (u32)ilen, sig) != 0) {
        console_write("pkg update: repository index signature invalid, update refused\n"); return -1;
    }
    u32 new_ver = 0;
    int n = repo_parse_index(repo_idx, (u32)ilen, &new_ver, repo_entries, REPO_MAX_ENTRIES);
    if (n < 0) {
        console_write("pkg update: malformed repository index, update refused\n"); return -1;
    }
    /* Anti-rollback against the stored index (if it is intact). */
    if (old_ok && new_ver < old_ver) {
        console_write("pkg update: stale index refused (older than stored index)\n"); return -1;
    }
    if (fs_write("repo_index.txt", (const u8 *)repo_idx, (u32)ilen, 0, 0600) != 0 ||
        fs_write("repo_index.sig", (const u8 *)repo_sig_txt, 512, 0, 0600) != 0) {
        console_write("pkg update: cannot store repository index\n"); return -1;
    }
    console_printf("Repository index updated: %d package(s), version %u\n", n, new_ver);
    return 0;
}

int pkg_repo_fetch(const char *name) {
    if (!fs_mounted()) { console_write("pkg: no filesystem\n"); return -1; }
    if (!valid_pkg_name(name)) { console_write("pkg fetch: invalid package name\n"); return -1; }
    char url[128];
    if (repo_read_config(url, sizeof(url)) != 0) {
        console_write("pkg fetch: no repository set (pkg repo <host[:port][/prefix]> first)\n"); return -1;
    }
    struct repo_entry e;
    if (repo_find(name, &e) != 0) {
        console_write("pkg fetch: package not in repository index (run pkg update)\n"); return -1;
    }
    char target[40];
    {
        u32 nl = strlen(name);
        memcpy(target, name, nl);
        memcpy(target + nl, ".nxpkg", 7);
    }
    if (fs_exists(target)) {
        console_write("pkg fetch: file already exists (remove it first)\n"); return -1;
    }
    char host[64], prefix[64]; u16 port = 80;
    if (repo_parse_url(url, host, sizeof(host), &port, prefix, sizeof(prefix)) != 0) {
        console_write("pkg fetch: stored repository URL is malformed\n"); return -1;
    }
    char path[128];
    {
        u32 pl = strlen(prefix);
        while (pl > 0 && prefix[pl - 1] == '/') pl--;
        u32 pi = 0;
        path[pi++] = '/';
        for (u32 i = 0; i < pl; i++) path[pi++] = prefix[i];
        if (pl > 0) path[pi++] = '/';
        const char *fn = e.file;
        while (*fn) path[pi++] = *fn++;
        path[pi] = 0;
    }
    int bl = repo_download(host, port, path, &e);
    if (bl < 0) return -1;
    if (fs_write(target, pkg_buf, (u32)bl, 0, 0644) != 0) {
        console_write("pkg fetch: cannot save package file\n"); return -1;
    }
    console_printf("Fetched %s %s\n", e.name, e.version);
    return 0;
}

int pkg_repo_install(const char *name) {
    if (!fs_mounted()) { console_write("pkg: no filesystem\n"); return -1; }
    if (!valid_pkg_name(name)) { console_write("pkg install: invalid package name\n"); return -1; }
    char url[128];
    if (repo_read_config(url, sizeof(url)) != 0) {
        console_write("pkg install: no repository set (pkg repo <host[:port][/prefix]> first)\n"); return -1;
    }
    struct repo_entry e;
    if (repo_find(name, &e) != 0) {
        console_write("pkg install: package not in repository index (run pkg update)\n"); return -1;
    }
    char host[64], prefix[64]; u16 port = 80;
    if (repo_parse_url(url, host, sizeof(host), &port, prefix, sizeof(prefix)) != 0) {
        console_write("pkg install: stored repository URL is malformed\n"); return -1;
    }
    char path[128];
    {
        u32 pl = strlen(prefix);
        while (pl > 0 && prefix[pl - 1] == '/') pl--;
        u32 pi = 0;
        path[pi++] = '/';
        for (u32 i = 0; i < pl; i++) path[pi++] = prefix[i];
        if (pl > 0) path[pi++] = '/';
        const char *fn = e.file;
        while (*fn) path[pi++] = *fn++;
        path[pi] = 0;
    }
    const char *tmp = "rep0.nxpkg";
    if (fs_exists(tmp)) {
        console_write("pkg install: temporary file collision\n"); return -1;
    }
    int bl = repo_download(host, port, path, &e);
    if (bl < 0) return -1;
    if (fs_write(tmp, pkg_buf, (u32)bl, 0, 0644) != 0) {
        console_write("pkg install: temporary file write failed\n");
        fs_delete(tmp);
        return -1;
    }
    int r = pkg_install(tmp);
    fs_delete(tmp);
    return r;
}
