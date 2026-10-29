/* HTTP layer (web/SSL Phase 4): response parsing, chunked
   decoding, cookie jar, redirect resolution, and the
   redirect + cookie fetch wrappers.
   Security invariants (see docs/WEB_SSL.md Phase 4 appendix):
   - No https->http downgrade, ever: refused before fetching.
   - The legacy single-use flag is consumed by hop 1 only;
     later hops never re-arm it, so a redirect to a
     legacy-only target fails its modern handshake.
   - Cookies are scoped by domain/path, Secure cookies only
     over TLS, and never sent to a host the domain forbids.
   - The repo path does not use this file's wrappers at all.
   All large buffers are file-scope statics: the kernel stack
   is 16 KiB and fetch callers already run deep. */
#include "net.h"
#include "http.h"
#include "../drivers/pit.h"

/* ---------- small string helpers (no strcpy/strchr in-tree) ---------- */
static int http_lower(int c) {
    if (c >= 'A' && c <= 'Z') return c + 32;
    return c;
}
static u32 http_copy(char *dst, const char *src, u32 max) {
    /* Copy at most max-1 chars + NUL. Returns 1 if everything
       fit, 0 if truncated. */
    u32 i = 0;
    if (max == 0) return 0;
    while (src[i] && i + 1 < max) { dst[i] = src[i]; i++; }
    dst[i] = 0;
    return src[i] == 0;
}
static int http_name_eq(const char *a, u32 alen, const char *b) {
    u32 blen = strlen(b);
    if (alen != blen) return 0;
    for (u32 i = 0; i < alen; i++)
        if (http_lower((u8)a[i]) != http_lower((u8)b[i])) return 0;
    return 1;
}
static int http_starts_ci(const char *s, const char *prefix) {
    while (*prefix) {
        if (http_lower((u8)*s) != http_lower((u8)*prefix)) return 0;
        s++; prefix++;
    }
    return 1;
}

/* ---------- header scanning ---------- */
/* Find the line [start, header_end) bounds: returns the line
   length excluding CRLF, or -1 when the line is unterminated. */
static int http_line_len(const char *buf, u32 start, u32 header_end) {
    u32 i = start;
    while (i + 1 < header_end) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') return (int)(i - start);
        i++;
    }
    return -1;
}

int http_parse_status(const char *buf, u32 header_end) {
    int ll = http_line_len(buf, 0, header_end);
    if (ll < 0) return -1;
    if (ll < 12) return -1; /* "HTTP/1.x NNN" at minimum */
    if (buf[0] != 'H' || buf[1] != 'T' || buf[2] != 'T' || buf[3] != 'P' ||
        buf[4] != '/') return -1;
    u32 i = 5;
    while (i < (u32)ll && buf[i] != ' ') i++;
    if (i >= (u32)ll) return -1;
    while (i < (u32)ll && buf[i] == ' ') i++;
    if (i + 3 > (u32)ll) return -1;
    int code = 0;
    for (int k = 0; k < 3; k++) {
        char c = buf[i + (u32)k];
        if (c < '0' || c > '9') return -1;
        code = code * 10 + (c - '0');
    }
    return code;
}

int http_header_value(const char *buf, u32 header_end, const char *name,
                      char *out, u32 out_max) {
    u32 pos = 0;
    /* Skip the status line. */
    int ll = http_line_len(buf, 0, header_end);
    if (ll < 0) return -1;
    pos = (u32)ll + 2;
    while (pos < header_end) {
        ll = http_line_len(buf, pos, header_end);
        if (ll < 0) return -1;
        if (ll == 0) return -1; /* blank line: end of headers */
        u32 line = pos;
        pos += (u32)ll + 2;
        /* Find the colon. */
        u32 colon = line;
        while (colon < line + (u32)ll && buf[colon] != ':') colon++;
        if (colon >= line + (u32)ll) continue; /* no colon: skip */
        if (!http_name_eq(buf + line, colon - line, name)) continue;
        u32 v = colon + 1;
        while (v < line + (u32)ll && (buf[v] == ' ' || buf[v] == '\t')) v++;
        u32 vend = line + (u32)ll;
        while (vend > v && (buf[vend - 1] == ' ' || buf[vend - 1] == '\t')) vend--;
        if (vend - v >= out_max) return -2;
        for (u32 i = v; i < vend; i++) out[i - v] = buf[i];
        out[vend - v] = 0;
        return 0;
    }
    return -1;
}

/* Parse one header value's leading decimal; strict: digits then
   only spaces to end of line. Returns 0 ok, -1 malformed. */
static int http_parse_u32(const char *s, u32 len, u32 *out) {
    u32 i = 0, v = 0;
    while (i < len && s[i] == ' ') i++;
    if (i >= len) return -1;
    int digits = 0;
    while (i < len && s[i] >= '0' && s[i] <= '9') {
        u32 d = (u32)(s[i] - '0');
        if (v > (0xFFFFFFFFu - d) / 10u) return -1;
        v = v * 10 + d;
        digits++; i++;
    }
    if (!digits) return -1;
    while (i < len && s[i] == ' ') i++;
    if (i != len) return -1;
    *out = v;
    return 0;
}

/* Iterate header lines, calling fn(value_ptr, value_len) for
   each line whose name matches (case-insensitive). Stops and
   returns -1 on a malformed line. */
static int http_each_header(const char *buf, u32 header_end,
                            const char *name,
                            int (*fn)(const char *, u32, void *),
                            void *ctx) {
    u32 pos = 0;
    int ll = http_line_len(buf, 0, header_end);
    if (ll < 0) return -1;
    pos = (u32)ll + 2;
    while (pos < header_end) {
        ll = http_line_len(buf, pos, header_end);
        if (ll < 0) return -1;
        if (ll == 0) return 0;
        u32 line = pos;
        pos += (u32)ll + 2;
        u32 colon = line;
        while (colon < line + (u32)ll && buf[colon] != ':') colon++;
        if (colon >= line + (u32)ll) continue;
        if (!http_name_eq(buf + line, colon - line, name)) continue;
        u32 v = colon + 1;
        while (v < line + (u32)ll && (buf[v] == ' ' || buf[v] == '\t')) v++;
        u32 vend = line + (u32)ll;
        while (vend > v && (buf[vend - 1] == ' ' || buf[vend - 1] == '\t')) vend--;
        if (fn(buf + v, vend - v, ctx) != 0) return -1;
    }
    return 0;
}

struct cl_ctx { u32 val; int seen; };
static int cl_fn(const char *v, u32 len, void *ctx) {
    struct cl_ctx *c = (struct cl_ctx *)ctx;
    u32 val;
    if (http_parse_u32(v, len, &val) != 0) return -1;
    if (c->seen && c->val != val) return -1; /* conflicting dup */
    c->val = val; c->seen = 1;
    return 0;
}
int http_content_length(const char *buf, u32 header_end, u32 *len_out) {
    struct cl_ctx c;
    c.val = 0; c.seen = 0;
    if (http_each_header(buf, header_end, "Content-Length", cl_fn, &c) != 0)
        return -1;
    *len_out = c.seen ? c.val : 0xFFFFFFFFu;
    return 0;
}

struct te_ctx { int chunked; };
static int te_fn(const char *v, u32 len, void *ctx) {
    struct te_ctx *t = (struct te_ctx *)ctx;
    /* Value must be exactly "chunked" (case-insensitive). */
    if (len != 7) return -1;
    if (!http_name_eq(v, len, "chunked")) return -1;
    t->chunked = 1;
    return 0;
}
int http_is_chunked(const char *buf, u32 header_end) {
    struct te_ctx t;
    t.chunked = 0;
    if (http_each_header(buf, header_end, "Transfer-Encoding", te_fn, &t) != 0)
        return -1;
    return t.chunked;
}

/* ---------- chunked decoding ---------- */
static int http_hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
int http_chunked_decode(char *buf, u32 header_end, u32 total,
                        int truncated, u32 *body_len_out) {
    u32 pos = header_end, dst = header_end;
    for (;;) {
        /* Find the chunk-size line's CRLF. */
        u32 le = pos;
        int found = 0;
        while (le + 1 < total) {
            if (buf[le] == '\r' && buf[le + 1] == '\n') { found = 1; break; }
            le++;
        }
        if (!found) {
            if (truncated) break; /* partial: keep what decoded */
            return -1;
        }
        /* Parse hex size; ';' starts extensions (ignored);
           spaces/tabs allowed between size and ';'/EOL. */
        u32 sz = 0, i = pos;
        int digits = 0;
        while (i < le) {
            int hv = http_hex_val(buf[i]);
            if (hv < 0) break;
            if (sz > (0xFFFFFFFFu - (u32)hv) / 16u) return -1;
            sz = sz * 16 + (u32)hv;
            digits++; i++;
        }
        if (!digits) return -1;
        while (i < le && (buf[i] == ' ' || buf[i] == '\t')) i++;
        if (i < le && buf[i] != ';') return -1;
        pos = le + 2;
        if (sz == 0) {
            /* Trailers: skip lines to the blank line or EOF. */
            for (;;) {
                if (pos >= total) break;
                u32 tle = pos;
                int tfound = 0;
                while (tle + 1 < total) {
                    if (buf[tle] == '\r' && buf[tle + 1] == '\n') {
                        tfound = 1; break;
                    }
                    tle++;
                }
                if (!tfound) { pos = total; break; }
                if (tle == pos) { pos = tle + 2; break; }
                pos = tle + 2;
            }
            break;
        }
        /* Need sz data bytes + CRLF. */
        u32 avail = total - pos;
        if (avail < 2 || sz > avail - 2) {
            if (truncated) break; /* partial: keep what decoded */
            return -1;
        }
        if (buf[pos + sz] != '\r' || buf[pos + sz + 1] != '\n') return -1;
        memmove(buf + dst, buf + pos, sz);
        dst += sz;
        pos += sz + 2;
    }
    *body_len_out = dst - header_end;
    buf[header_end + *body_len_out] = 0;
    return 0;
}

/* ---------- cookie jar ---------- */
#define HTTP_COOKIE_MAX 16
struct http_cookie {
    char name[64];
    char value[128];
    char domain[64];
    char path[64];
    u32 expiry; /* 0 = session; else timer_ticks deadline (100 Hz) */
    u32 seq;    /* insertion order, for eviction */
    u8 secure;
    u8 host_only;
    u8 used;
};
static struct http_cookie http_jar[HTTP_COOKIE_MAX];
static u32 http_jar_seq = 0;

static int http_ci_eq(const char *a, const char *b) {
    while (*a && *b) {
        if (http_lower((u8)*a) != http_lower((u8)*b)) return 0;
        a++; b++;
    }
    return *a == *b;
}
/* Domain match: host-only needs exact equality; otherwise the
   host must equal the domain or end with "." + domain
   (case-insensitive). */
static int http_domain_match(const char *domain, int host_only,
                             const char *host) {
    if (host_only) return http_ci_eq(domain, host);
    u32 dl = strlen(domain), hl = strlen(host);
    if (hl == dl) return http_ci_eq(domain, host);
    if (hl < dl + 1) return 0;
    if (host[hl - dl - 1] != '.') return 0;
    return http_ci_eq(domain, host + (hl - dl));
}
/* Path match (RFC 6265 5.1.4): equal, or the cookie path is a
   prefix ending at a '/' boundary. */
static int http_path_match(const char *cpath, const char *rpath) {
    u32 cl = strlen(cpath), rl = strlen(rpath);
    if (rl < cl) return 0;
    for (u32 i = 0; i < cl; i++)
        if (cpath[i] != rpath[i]) return 0;
    if (rl == cl) return 1;
    if (cpath[cl - 1] == '/') return 1;
    return rpath[cl] == '/';
}
static int http_cookie_expired(struct http_cookie *c) {
    if (c->expiry == 0) return 0;
    /* Wrap-safe: expired iff now is at/past expiry within
       2^31 ticks (~248 days), which covers any real uptime. */
    return (timer_ticks - c->expiry) < 0x80000000u;
}

/* Parse one Set-Cookie value. line/len excludes CRLF. */
void http_cookie_store(const char *line, u32 len, const char *host,
                       const char *path, int is_tls) {
    (void)is_tls; /* Secure only gates SENDING, not storing. */
    /* name=value up to the first ';'. */
    u32 semi = 0;
    while (semi < len && line[semi] != ';') semi++;
    u32 eq = 0;
    while (eq < semi && line[eq] != '=') eq++;
    if (eq == 0 || eq >= semi) return; /* empty name or no '=' */
    /* Validate the name: no spaces, controls, ';', or '=' inside. */
    for (u32 i = 0; i < eq; i++) {
        char c = line[i];
        if (c <= ' ' || c == ';' || c == '=') return;
    }
    if (eq >= 64) return; /* overlong name: refused, not truncated */
    u32 vs = eq + 1, ve = semi;
    while (vs < ve && (line[vs] == ' ' || line[vs] == '\t')) vs++;
    while (ve > vs && (line[ve - 1] == ' ' || line[ve - 1] == '\t')) ve--;
    if (ve - vs >= 128) return; /* overlong value: refused */
    char name[64], value[128];
    for (u32 i = 0; i < eq; i++) name[i] = line[i];
    name[eq] = 0;
    for (u32 i = vs; i < ve; i++) value[i - vs] = line[i];
    value[ve - vs] = 0;

    /* Defaults: host-only domain, request directory path. */
    char domain[64], cpath[64];
    if (!http_copy(domain, host, sizeof(domain))) return;
    for (u32 i = 0; domain[i]; i++) domain[i] = (char)http_lower((u8)domain[i]);
    int host_only = 1;
    u32 plen = strlen(path), slash = 0;
    int found_slash = 0;
    for (u32 i = 0; i < plen; i++) {
        if (path[i] == '/') { slash = i; found_slash = 1; }
    }
    if (found_slash) {
        u32 dl = slash + 1;
        if (dl >= 64) return;
        for (u32 i = 0; i < dl; i++) cpath[i] = path[i];
        cpath[dl] = 0;
    } else {
        cpath[0] = '/'; cpath[1] = 0;
    }
    int secure = 0;
    int have_maxage = 0;
    s32 maxage = 0;
    /* Attributes after the first ';'. */
    u32 pos = semi;
    while (pos < len) {
        pos++; /* skip ';' */
        while (pos < len && (line[pos] == ' ' || line[pos] == '\t')) pos++;
        u32 astart = pos;
        while (pos < len && line[pos] != ';') pos++;
        u32 aend = pos;
        while (aend > astart && (line[aend - 1] == ' ' || line[aend - 1] == '\t')) aend--;
        u32 aeq = astart;
        while (aeq < aend && line[aeq] != '=') aeq++;
        if (http_name_eq(line + astart, (aeq > astart ? aeq - astart : 0), "secure") &&
            aeq == aend) {
            secure = 1;
        } else if (aeq < aend &&
                   http_name_eq(line + astart, aeq - astart, "path")) {
            u32 v = aeq + 1;
            while (v < aend && (line[v] == ' ' || line[v] == '\t')) v++;
            if (v < aend && line[v] == '/' && aend - v < 64) {
                for (u32 i = v; i < aend; i++) cpath[i - v] = line[i];
                cpath[aend - v] = 0;
            }
            /* A Path not starting with '/' is ignored. */
        } else if (aeq < aend &&
                   http_name_eq(line + astart, aeq - astart, "domain")) {
            u32 v = aeq + 1;
            while (v < aend && (line[v] == ' ' || line[v] == '\t')) v++;
            u32 vend = aend;
            while (vend > v && (line[vend - 1] == ' ' || line[vend - 1] == '\t')) vend--;
            if (v < vend && line[v] == '.') v++;
            if (v >= vend || vend - v >= 64) return; /* bad domain */
            for (u32 i = v; i < vend; i++)
                domain[i - v] = (char)http_lower((u8)line[i]);
            domain[vend - v] = 0;
            host_only = 0;
        } else if (aeq < aend &&
                   http_name_eq(line + astart, aeq - astart, "max-age")) {
            u32 v = aeq + 1;
            while (v < aend && (line[v] == ' ' || line[v] == '\t')) v++;
            int neg = 0;
            if (v < aend && line[v] == '-') { neg = 1; v++; }
            u32 aval = 0;
            int digits = 0, over = 0;
            while (v < aend && line[v] >= '0' && line[v] <= '9') {
                if (aval > (0xFFFFFFFFu - 9u) / 10u) over = 1;
                else aval = aval * 10 + (u32)(line[v] - '0');
                digits++; v++;
            }
            if (digits) {
                have_maxage = 1;
                /* Clamp: a Max-Age past s32 range (68 years)
                   is a far-future cookie, not a delete. */
                if (over || aval > 0x7FFFFFFFu) maxage = 0x7FFFFFFFL;
                else maxage = neg ? -(s32)aval : (s32)aval;
            }
            /* A malformed Max-Age is ignored (session cookie). */
        }
        /* "expires" and unknown attributes are ignored: only
           Max-Age drives expiry (documented in WEB_SSL.md). */
    }
    /* A Domain attribute must be a suffix of the response host,
       or the cookie is refused (no cross-host planting). */
    if (!host_only && !http_domain_match(domain, 0, host)) return;
    /* Max-Age <= 0 deletes a matching cookie. */
    if (have_maxage && maxage <= 0) {
        for (int i = 0; i < HTTP_COOKIE_MAX; i++) {
            if (http_jar[i].used && strcmp(http_jar[i].name, name) == 0 &&
                strcmp(http_jar[i].domain, domain) == 0 &&
                strcmp(http_jar[i].path, cpath) == 0)
                http_jar[i].used = 0;
        }
        return;
    }
    u32 expiry = 0;
    if (have_maxage) {
        u32 age = (u32)maxage;
        u32 maxinc = (0xFFFFFFFFu - timer_ticks) / 100u;
        if (age > maxinc) expiry = 0xFFFFFFFFu;
        else expiry = timer_ticks + age * 100u;
    }
    /* Replace an existing cookie, else take a free slot, else
       evict the oldest entry. */
    int slot = -1;
    for (int i = 0; i < HTTP_COOKIE_MAX; i++) {
        if (http_jar[i].used && strcmp(http_jar[i].name, name) == 0 &&
            strcmp(http_jar[i].domain, domain) == 0 &&
            strcmp(http_jar[i].path, cpath) == 0) { slot = i; break; }
    }
    if (slot < 0) {
        for (int i = 0; i < HTTP_COOKIE_MAX; i++)
            if (!http_jar[i].used) { slot = i; break; }
    }
    if (slot < 0) {
        u32 oldest = 0xFFFFFFFFu;
        for (int i = 0; i < HTTP_COOKIE_MAX; i++)
            if (http_jar[i].seq < oldest) { oldest = http_jar[i].seq; slot = i; }
    }
    struct http_cookie *c = &http_jar[slot];
    memset(c, 0, sizeof(*c));
    for (u32 i = 0; name[i]; i++) c->name[i] = name[i];
    for (u32 i = 0; value[i]; i++) c->value[i] = value[i];
    for (u32 i = 0; domain[i]; i++) c->domain[i] = domain[i];
    for (u32 i = 0; cpath[i]; i++) c->path[i] = cpath[i];
    c->expiry = expiry;
    c->seq = http_jar_seq++;
    c->secure = secure ? 1 : 0;
    c->host_only = host_only ? 1 : 0;
    c->used = 1;
}

void http_store_all_cookies(const char *buf, u32 header_end,
                            const char *host, const char *path, int is_tls) {
    u32 pos = 0;
    int ll = http_line_len(buf, 0, header_end);
    if (ll < 0) return;
    pos = (u32)ll + 2;
    while (pos < header_end) {
        ll = http_line_len(buf, pos, header_end);
        if (ll < 0) return;
        if (ll == 0) return;
        u32 line = pos;
        pos += (u32)ll + 2;
        u32 colon = line;
        while (colon < line + (u32)ll && buf[colon] != ':') colon++;
        if (colon >= line + (u32)ll) continue;
        if (!http_name_eq(buf + line, colon - line, "Set-Cookie")) continue;
        u32 v = colon + 1;
        while (v < line + (u32)ll && (buf[v] == ' ' || buf[v] == '\t')) v++;
        http_cookie_store(buf + v, line + (u32)ll - v, host, path, is_tls);
    }
}

int http_cookie_header(const char *host, const char *path, int is_tls,
                       char *out, u32 out_max) {
    u32 len = 0;
    out[0] = 0;
    for (int i = 0; i < HTTP_COOKIE_MAX; i++) {
        struct http_cookie *c = &http_jar[i];
        if (!c->used) continue;
        if (http_cookie_expired(c)) continue;
        if (c->secure && !is_tls) continue;
        if (!http_domain_match(c->domain, c->host_only, host)) continue;
        if (!http_path_match(c->path, path)) continue;
        u32 nl = strlen(c->name), vl = strlen(c->value);
        u32 need = nl + 1 + vl + (len ? 2 : 0);
        if (len + need >= out_max) return -1; /* never partial */
        if (len) { out[len++] = ';'; out[len++] = ' '; }
        for (u32 k = 0; k < nl; k++) out[len++] = c->name[k];
        out[len++] = '=';
        for (u32 k = 0; k < vl; k++) out[len++] = c->value[k];
        out[len] = 0;
    }
    return 0;
}

void http_cookies_list(void) {
    int n = 0;
    for (int i = 0; i < HTTP_COOKIE_MAX; i++) {
        struct http_cookie *c = &http_jar[i];
        if (!c->used) continue;
        if (http_cookie_expired(c)) { c->used = 0; continue; }
        n++;
        if (c->expiry == 0) {
            console_printf("cookie: %s=%s domain=%s path=%s%s session\n",
                           c->name, c->value, c->domain, c->path,
                           c->secure ? " Secure" : "");
        } else {
            u32 left = (c->expiry - timer_ticks) / 100u;
            console_printf("cookie: %s=%s domain=%s path=%s%s %u seconds left\n",
                           c->name, c->value, c->domain, c->path,
                           c->secure ? " Secure" : "", left);
        }
    }
    if (n == 0) console_write("cookie: (no cookies stored)\n");
}

int http_cookies_clear(void) {
    int n = 0;
    for (int i = 0; i < HTTP_COOKIE_MAX; i++)
        if (http_jar[i].used) { http_jar[i].used = 0; n++; }
    return n;
}

/* ---------- Location resolution ---------- */
static void http_resolve_err(char *err_out, u32 err_max, const char *msg) {
    if (err_max) http_copy(err_out, msg, err_max);
}
/* Copy path with '.'/'..' segment collapsing. in is NUL-
   terminated, starts with '/'. Returns 1 ok, 0 if it would
   overflow out_max. */
static int http_collapse_path(const char *in, char *out, u32 out_max) {
    /* Segment stack: offsets into out. File-scope would be
       nicer, but the segments live inside out itself: keep a
       small local stack of segment end offsets (path <= 127
       chars, so at most 64 segments). */
    u32 seg_end[64];
    int nseg = 0;
    u32 olen = 0;
    out[0] = 0;
    u32 i = 0;
    if (in[0] != '/') return 0;
    while (in[i]) {
        while (in[i] == '/') i++;
        if (!in[i]) break;
        u32 s = i;
        while (in[i] && in[i] != '/') i++;
        u32 sl = i - s;
        if (sl == 1 && in[s] == '.') continue;
        if (sl == 2 && in[s] == '.' && in[s + 1] == '.') {
            if (nseg > 0) {
                nseg--;
                olen = nseg > 0 ? seg_end[nseg - 1] : 0;
                out[olen] = 0;
            }
            continue;
        }
        if (nseg >= 64) return 0;
        if (olen + 1 + sl >= out_max) return 0;
        out[olen++] = '/';
        for (u32 k = 0; k < sl; k++) out[olen++] = in[s + k];
        out[olen] = 0;
        seg_end[nseg++] = olen;
    }
    if (olen == 0) {
        if (out_max < 2) return 0;
        out[0] = '/'; out[1] = 0;
    }
    return 1;
}

int http_resolve_location(const char *loc, int cur_tls,
                          const char *cur_host, u16 cur_port,
                          const char *cur_path,
                          int *tls_out, char *host_out, u32 host_max,
                          u16 *port_out, char *path_out, u32 path_max,
                          char *err_out, u32 err_max) {
    /* Trim spaces, strip the fragment. */
    while (*loc == ' ' || *loc == '\t') loc++;
    u32 llen = strlen(loc);
    while (llen > 0 && (loc[llen - 1] == ' ' || loc[llen - 1] == '\t')) llen--;
    u32 frag = 0;
    while (frag < llen && loc[frag] != '#') frag++;
    llen = frag;
    if (llen == 0) {
        http_resolve_err(err_out, err_max, "redirect with empty Location");
        return -1;
    }
    int tls = cur_tls;
    char nhost[64];
    u16 nport = cur_port;
    /* Work buffer for the merged path (fragment already cut). */
    static char merged[256];
    u32 mlen = 0;
    if (http_starts_ci(loc, "http://") || http_starts_ci(loc, "https://")) {
        int is_https = http_starts_ci(loc, "https://");
        tls = is_https ? 1 : 0;
        const char *auth = loc + (is_https ? 8 : 7);
        u32 alen = llen - (is_https ? 8 : 7);
        u32 slash = 0;
        while (slash < alen && auth[slash] != '/') slash++;
        if (slash == 0) {
            http_resolve_err(err_out, err_max, "redirect with empty host");
            return -1;
        }
        /* userinfo hides the real host: refuse. */
        for (u32 k = 0; k < slash; k++) {
            if (auth[k] == '@') {
                http_resolve_err(err_out, err_max,
                                 "redirect with userinfo refused");
                return -1;
            }
        }
        u32 hlen = slash, plen = 0;
        for (u32 k = 0; k < slash; k++) {
            if (auth[k] == ':') { hlen = k; plen = slash - k - 1; break; }
        }
        if (hlen == 0 || hlen >= 64) {
            http_resolve_err(err_out, err_max, "redirect host too long");
            return -1;
        }
        for (u32 k = 0; k < hlen; k++) nhost[k] = auth[k];
        nhost[hlen] = 0;
        nport = tls ? 443 : 80;
        if (plen) {
            u32 v = 0;
            int digits = 0;
            for (u32 k = 0; k < plen; k++) {
                char c = auth[hlen + 1 + k];
                if (c < '0' || c > '9') {
                    http_resolve_err(err_out, err_max,
                                     "redirect with bad port");
                    return -1;
                }
                if (v > (65535u - 9u) / 10u) {
                    http_resolve_err(err_out, err_max,
                                     "redirect with bad port");
                    return -1;
                }
                v = v * 10 + (u32)(c - '0');
                digits++;
            }
            if (!digits || v < 1 || v > 65535) {
                http_resolve_err(err_out, err_max, "redirect with bad port");
                return -1;
            }
            nport = (u16)v;
        }
        if (slash < alen) {
            mlen = alen - slash;
            if (mlen >= sizeof(merged)) {
                http_resolve_err(err_out, err_max, "redirect path too long");
                return -1;
            }
            for (u32 k = 0; k < mlen; k++) merged[k] = auth[slash + k];
            merged[mlen] = 0;
        } else {
            merged[0] = '/'; merged[1] = 0; mlen = 1;
        }
    } else if (llen >= 2 && loc[0] == '/' && loc[1] == '/') {
        /* Scheme-relative: same scheme, new authority. */
        const char *auth = loc + 2;
        u32 alen = llen - 2;
        u32 slash = 0;
        while (slash < alen && auth[slash] != '/') slash++;
        if (slash == 0) {
            http_resolve_err(err_out, err_max, "redirect with empty host");
            return -1;
        }
        for (u32 k = 0; k < slash; k++) {
            if (auth[k] == '@') {
                http_resolve_err(err_out, err_max,
                                 "redirect with userinfo refused");
                return -1;
            }
        }
        u32 hlen = slash, plen = 0;
        for (u32 k = 0; k < slash; k++) {
            if (auth[k] == ':') { hlen = k; plen = slash - k - 1; break; }
        }
        if (hlen == 0 || hlen >= 64) {
            http_resolve_err(err_out, err_max, "redirect host too long");
            return -1;
        }
        for (u32 k = 0; k < hlen; k++) nhost[k] = auth[k];
        nhost[hlen] = 0;
        nport = tls ? 443 : 80;
        if (plen) {
            u32 v = 0;
            int digits = 0;
            for (u32 k = 0; k < plen; k++) {
                char c = auth[hlen + 1 + k];
                if (c < '0' || c > '9') {
                    http_resolve_err(err_out, err_max,
                                     "redirect with bad port");
                    return -1;
                }
                if (v > (65535u - 9u) / 10u) {
                    http_resolve_err(err_out, err_max,
                                     "redirect with bad port");
                    return -1;
                }
                v = v * 10 + (u32)(c - '0');
                digits++;
            }
            if (!digits || v < 1 || v > 65535) {
                http_resolve_err(err_out, err_max, "redirect with bad port");
                return -1;
            }
            nport = (u16)v;
        }
        if (slash < alen) {
            mlen = alen - slash;
            if (mlen >= sizeof(merged)) {
                http_resolve_err(err_out, err_max, "redirect path too long");
                return -1;
            }
            for (u32 k = 0; k < mlen; k++) merged[k] = auth[slash + k];
            merged[mlen] = 0;
        } else {
            merged[0] = '/'; merged[1] = 0; mlen = 1;
        }
    } else if (loc[0] == '/') {
        /* Absolute path: same scheme/host/port. */
        if (!http_copy(nhost, cur_host, sizeof(nhost))) {
            http_resolve_err(err_out, err_max, "redirect host too long");
            return -1;
        }
        mlen = llen;
        if (mlen >= sizeof(merged)) {
            http_resolve_err(err_out, err_max, "redirect path too long");
            return -1;
        }
        for (u32 k = 0; k < mlen; k++) merged[k] = loc[k];
        merged[mlen] = 0;
    } else if (loc[0] == '?') {
        /* Query-only: same path up to any existing '?'. */
        if (!http_copy(nhost, cur_host, sizeof(nhost))) {
            http_resolve_err(err_out, err_max, "redirect host too long");
            return -1;
        }
        u32 cl = strlen(cur_path), q = 0;
        while (q < cl && cur_path[q] != '?') q++;
        if (q + llen >= sizeof(merged)) {
            http_resolve_err(err_out, err_max, "redirect path too long");
            return -1;
        }
        for (u32 k = 0; k < q; k++) merged[k] = cur_path[k];
        for (u32 k = 0; k < llen; k++) merged[q + k] = loc[k];
        mlen = q + llen;
        merged[mlen] = 0;
    } else {
        /* Relative path: merge with the current directory,
           then collapse '.' and '..' segments. A query part
           (after '?') is carried verbatim, uncollapsed. */
        if (!http_copy(nhost, cur_host, sizeof(nhost))) {
            http_resolve_err(err_out, err_max, "redirect host too long");
            return -1;
        }
        u32 q = 0;
        while (q < llen && loc[q] != '?') q++;
        /* Directory of the current path (through last '/'). */
        u32 cl = strlen(cur_path), dir = 0;
        for (u32 k = 0; k < cl; k++)
            if (cur_path[k] == '/') dir = k + 1;
        static char joined[256];
        u32 jl = 0;
        if (dir >= sizeof(joined) || q >= sizeof(joined) - dir) {
            http_resolve_err(err_out, err_max, "redirect path too long");
            return -1;
        }
        for (u32 k = 0; k < dir; k++) joined[jl++] = cur_path[k];
        for (u32 k = 0; k < q; k++) joined[jl++] = loc[k];
        joined[jl] = 0;
        static char collapsed[192];
        if (!http_collapse_path(joined, collapsed, sizeof(collapsed))) {
            http_resolve_err(err_out, err_max, "redirect path too long");
            return -1;
        }
        mlen = strlen(collapsed);
        if (mlen + (llen - q) >= sizeof(merged)) {
            http_resolve_err(err_out, err_max, "redirect path too long");
            return -1;
        }
        for (u32 k = 0; k < mlen; k++) merged[k] = collapsed[k];
        for (u32 k = q; k < llen; k++) merged[mlen++] = loc[k];
        merged[mlen] = 0;
    }
    /* The downgrade check lives here so every caller gets it:
       a secure context never follows into an insecure one. */
    if (cur_tls && !tls) {
        http_resolve_err(err_out, err_max,
                         "redirect refused: https to http downgrade");
        return -1;
    }
    if (!http_copy(host_out, nhost, host_max)) {
        http_resolve_err(err_out, err_max, "redirect host too long");
        return -1;
    }
    if (mlen + 1 > path_max) {
        http_resolve_err(err_out, err_max, "redirect path too long");
        return -1;
    }
    for (u32 k = 0; k < mlen; k++) path_out[k] = merged[k];
    path_out[mlen] = 0;
    *tls_out = tls;
    *port_out = nport;
    return 0;
}

/* ---------- redirect + cookie wrappers ---------- */
static char http_last_error[128];
static char http_cur_host[64];
static char http_cur_path[128];
static char http_next_host[64];
static char http_next_path[128];
static char http_visited[6][224];
static char http_cookie_hdr[512];
static char http_loc[256];

static void http_set_error(const char *msg) {
    http_copy(http_last_error, msg, sizeof(http_last_error));
}
const char *net_http_fetch_error(void) { return http_last_error; }

static void http_build_url(int tls, const char *host, u16 port,
                           const char *path, char *out, u32 out_max) {
    u32 o = 0;
    const char *scheme = tls ? "https://" : "http://";
    while (*scheme && o + 1 < out_max) out[o++] = *scheme++;
    const char *h = host;
    while (*h && o + 1 < out_max) out[o++] = *h++;
    char num[8];
    u32_to_str(port, num, 10);
    if (o + 1 < out_max) out[o++] = ':';
    const char *p = num;
    while (*p && o + 1 < out_max) out[o++] = *p++;
    p = path;
    while (*p && o + 1 < out_max) out[o++] = *p++;
    out[o] = 0;
}

static int http_fetch_internal(int is_tls, int mode, const char *host,
                               u16 port, const char *path, char *buf,
                               u32 max, int flags) {
    http_last_error[0] = 0;
    int cur_tls = is_tls;
    int cur_mode = mode;
    u16 cur_port = port;
    if (!http_copy(http_cur_host, host, sizeof(http_cur_host))) {
        http_set_error("host too long");
        return -1;
    }
    if (!http_copy(http_cur_path, path, sizeof(http_cur_path))) {
        http_set_error("path too long");
        return -1;
    }
    int nvisited = 0;
    for (int hop = 0; ; hop++) {
        char url[224];
        http_build_url(cur_tls, http_cur_host, cur_port, http_cur_path,
                       url, sizeof(url));
        for (int i = 0; i < nvisited; i++) {
            if (strcmp(url, http_visited[i]) == 0) {
                http_set_error("redirect loop detected");
                return -1;
            }
        }
        if (nvisited < 6) {
            http_copy(http_visited[nvisited], url, sizeof(http_visited[0]));
            nvisited++;
        }
        const char *cookie_hdr = 0;
        int store = 0;
        if (flags & HTTP_FETCH_USE_COOKIES) {
            store = 1;
            if (http_cookie_header(http_cur_host, http_cur_path, cur_tls,
                                  http_cookie_hdr,
                                  sizeof(http_cookie_hdr)) == 0 &&
                http_cookie_hdr[0])
                cookie_hdr = http_cookie_hdr;
        }
        int status = 0;
        http_loc[0] = 0;
        int r;
        if (cur_tls)
            r = https_get_single(cur_mode, http_cur_host, cur_port,
                                 http_cur_path, buf, max, cookie_hdr, store,
                                 &status, http_loc, sizeof(http_loc));
        else
            r = http_get_single(http_cur_host, cur_port, http_cur_path,
                                buf, max, cookie_hdr, store,
                                &status, http_loc, sizeof(http_loc));
        if (r == -2) return -2;
        if (r < 0) {
            if (hop > 0) http_set_error("redirect target fetch failed");
            return -1;
        }
        if ((status == 301 || status == 302 || status == 303 ||
             status == 307 || status == 308) && http_loc[0]) {
            if (!(flags & HTTP_FETCH_FOLLOW_REDIRECT)) {
                static char nferr[128];
                const char *pre = "redirect not followed: ";
                u32 o = 0;
                while (pre[o] && o + 1 < sizeof(nferr)) {
                    nferr[o] = pre[o]; o++;
                }
                const char *l = http_loc;
                while (*l && o + 1 < sizeof(nferr)) nferr[o++] = *l++;
                nferr[o] = 0;
                http_set_error(nferr);
                return -4;
            }
            if (hop >= 5) {
                http_set_error("redirect limit reached");
                return -1;
            }
            int next_tls;
            u16 next_port;
            char rerr[96];
            if (http_resolve_location(http_loc, cur_tls, http_cur_host,
                                      cur_port, http_cur_path, &next_tls,
                                      http_next_host, sizeof(http_next_host),
                                      &next_port, http_next_path,
                                      sizeof(http_next_path),
                                      rerr, sizeof(rerr)) != 0) {
                http_set_error(rerr);
                return -1;
            }
            /* The legacy single-use flag is deliberately NOT
               re-armed here: hop 1 consumed it if set, and
               every later hop negotiates modern TLS. A
               redirect to a legacy-only target therefore
               fails its handshake instead of silently
               downgrading. */
            cur_tls = next_tls;
            cur_port = next_port;
            http_copy(http_cur_host, http_next_host, sizeof(http_cur_host));
            http_copy(http_cur_path, http_next_path, sizeof(http_cur_path));
            continue;
        }
        return r;
    }
}

int net_http_fetch(const char *host, u16 port, const char *path,
                   char *buf, u32 max, int flags) {
    return http_fetch_internal(0, 0, host, port, path, buf, max, flags);
}
int net_https_fetch(int mode, const char *host, u16 port, const char *path,
                    char *buf, u32 max, int flags) {
    return http_fetch_internal(1, mode, host, port, path, buf, max, flags);
}
