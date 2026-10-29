/* Adversarial host test for the Phase 4 HTTP helpers (net/http.c),
   written for the v1.1.4 release security pass. Unlike
   tests/host_http.c (which proves the intended behaviour), this
   file probes hostile inputs: malformed statuses, duplicate /
   overflowing Content-Length, non-chunked Transfer-Encoding,
   malformed chunked bodies, cookie smuggling attempts
   (cross-host Domain, path-boundary confusion, overlong
   fields, Secure downgrade), and redirect attacks
   (downgrade, userinfo, bad ports, overlong targets).
   Build: gcc -fno-builtin -o /tmp/host_http_sec
   tests/host_http_sec.c net/http.c kernel/util.c
   (run from ~/workspace/nxtsOS). Exit 0 on PASS. */
#include <stdio.h>
#include <stdarg.h>
#include "../net/http.h"

volatile u32 timer_ticks = 0;

void console_write(const char *s) { fputs(s, stdout); }
void console_printf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}
/* Stubs: the wrappers reference the single-fetch cores, which
   are not linked into this test. */
int http_get_single(const char *h, u16 p, const char *pa, char *b, u32 m,
                    const char *c, int s, int *st, char *l, u32 lm) {
    (void)h; (void)p; (void)pa; (void)b; (void)m; (void)c; (void)s;
    (void)st; (void)l; (void)lm;
    return -1;
}
int https_get_single(int mode, const char *h, u16 p, const char *pa,
                     char *b, u32 m, const char *c, int s, int *st,
                     char *l, u32 lm) {
    (void)mode; (void)h; (void)p; (void)pa; (void)b; (void)m; (void)c;
    (void)s; (void)st; (void)l; (void)lm;
    return -1;
}

static int npass = 0, nfail = 0;
#define CHECK(cond, name) do { \
    if (cond) { npass++; } \
    else { nfail++; printf("FAIL: %s\n", name); } } while (0)

/* Small append helper (avoids libc string functions, whose
   size_t declarations conflict with kernel/common.h). */
static void ap(char *dst, u32 *pos, const char *s) {
    u32 i = 0;
    while (s[i]) { dst[*pos] = s[i]; (*pos)++; i++; }
    dst[*pos] = 0;
}
static u32 slen(const char *s) {
    u32 i = 0;
    while (s[i]) i++;
    return i;
}
static int seq(const char *a, const char *b) {
    u32 i = 0;
    while (a[i] && b[i]) { if (a[i] != b[i]) return 0; i++; }
    return a[i] == b[i];
}

/* Build "HTTP/1.1 <status>\r\n<headers>\r\n<body>" into buf;
   returns the header_end offset (start of body). */
static u32 mkresp(char *buf, const char *status, const char *headers,
                  const char *body) {
    u32 pos = 0;
    ap(buf, &pos, "HTTP/1.1 ");
    ap(buf, &pos, status);
    ap(buf, &pos, "\r\n");
    ap(buf, &pos, headers);
    ap(buf, &pos, "\r\n");
    u32 he = pos;
    ap(buf, &pos, body);
    return he;
}

int main(void) {
    static char buf[8192];
    static char out[512];
    static char host[64], path[256], err[96];
    u32 he, len, blen;
    int tls, r;
    u16 port;

    /* ---- status parsing ---- */
    he = mkresp(buf, "200 OK", "", "");
    CHECK(http_parse_status(buf, he) == 200, "status 200");
    he = mkresp(buf, "404 Not Found", "", "");
    CHECK(http_parse_status(buf, he) == 404, "status 404");
    he = mkresp(buf, "301 Moved", "Location: /x\r\n", "");
    CHECK(http_parse_status(buf, he) == 301, "status 301");
    /* Garbage status line: not HTTP/. */
    {
        u32 pos = 0;
        ap(buf, &pos, "HTTX/1.1 200 OK\r\n\r\n");
        CHECK(http_parse_status(buf, pos) == -1, "status garbage rejected");
    }
    {
        u32 pos = 0;
        ap(buf, &pos, "http/1.1 200 OK\r\n\r\n");
        CHECK(http_parse_status(buf, pos) == -1, "status lowercase rejected");
    }
    {
        u32 pos = 0;
        ap(buf, &pos, "HTTP/1.1 20\r\n\r\n");
        CHECK(http_parse_status(buf, pos) == -1, "status 2-digit rejected");
    }
    {
        u32 pos = 0;
        ap(buf, &pos, "HTTP/1.1\r\n\r\n");
        CHECK(http_parse_status(buf, pos) == -1, "status missing code rejected");
    }

    /* ---- header value ---- */
    he = mkresp(buf, "200 OK", "Content-Type: text/plain\r\nX-Test: AbC\r\n", "");
    CHECK(http_header_value(buf, he, "x-test", out, sizeof(out)) == 0 &&
          seq(out, "AbC"), "header case-insensitive");
    he = mkresp(buf, "200 OK", "X-Dup: first\r\nX-Dup: second\r\n", "");
    CHECK(http_header_value(buf, he, "x-dup", out, sizeof(out)) == 0 &&
          seq(out, "first"), "header first wins");
    he = mkresp(buf, "200 OK", "X-A: 1\r\n", "");
    CHECK(http_header_value(buf, he, "X-Missing", out, sizeof(out)) == -1,
          "header absent");
    he = mkresp(buf, "200 OK", "X-Long: abcdefghij\r\n", "");
    CHECK(http_header_value(buf, he, "X-Long", out, 5) == -2,
          "header too small out");
    he = mkresp(buf, "200 OK", "NoColonLine\r\nX-Ok: yes\r\n", "");
    CHECK(http_header_value(buf, he, "X-Ok", out, sizeof(out)) == 0 &&
          seq(out, "yes"), "header colon-less line skipped");

    /* ---- Content-Length ---- */
    he = mkresp(buf, "200 OK", "Content-Length: 42\r\n", "");
    CHECK(http_content_length(buf, he, &len) == 0 && len == 42, "CL normal");
    he = mkresp(buf, "200 OK", "Content-Length: 7\r\nContent-Length: 7\r\n", "");
    CHECK(http_content_length(buf, he, &len) == 0 && len == 7,
          "CL identical dup ok");
    he = mkresp(buf, "200 OK", "Content-Length: 7\r\nContent-Length: 8\r\n", "");
    CHECK(http_content_length(buf, he, &len) == -1, "CL conflicting dup refused");
    he = mkresp(buf, "200 OK", "Content-Length: 99999999999\r\n", "");
    CHECK(http_content_length(buf, he, &len) == -1, "CL overflow refused");
    he = mkresp(buf, "200 OK", "Content-Length: 12x\r\n", "");
    CHECK(http_content_length(buf, he, &len) == -1, "CL trailing junk refused");
    he = mkresp(buf, "200 OK", "Content-Length: -5\r\n", "");
    CHECK(http_content_length(buf, he, &len) == -1, "CL negative refused");
    he = mkresp(buf, "200 OK", "", "");
    CHECK(http_content_length(buf, he, &len) == 0 && len == 0xFFFFFFFFu,
          "CL absent");

    /* ---- Transfer-Encoding ---- */
    he = mkresp(buf, "200 OK", "Transfer-Encoding: chunked\r\n", "");
    CHECK(http_is_chunked(buf, he) == 1, "TE chunked");
    he = mkresp(buf, "200 OK", "Transfer-Encoding: Chunked\r\n", "");
    CHECK(http_is_chunked(buf, he) == 1, "TE Chunked case-insensitive");
    he = mkresp(buf, "200 OK", "Transfer-Encoding: gzip\r\n", "");
    CHECK(http_is_chunked(buf, he) == -1, "TE gzip refused");
    he = mkresp(buf, "200 OK", "Transfer-Encoding: chunked, gzip\r\n", "");
    CHECK(http_is_chunked(buf, he) == -1, "TE chunked+gzip refused");
    he = mkresp(buf, "200 OK", "", "");
    CHECK(http_is_chunked(buf, he) == 0, "TE absent");

    /* ---- chunked decoding ---- */
    he = mkresp(buf, "200 OK", "", "5\r\nhello\r\n0\r\n\r\n");
    r = http_chunked_decode(buf, he, slen(buf), 0, &blen);
    CHECK(r == 0 && blen == 5 && seq(buf + he, "hello"), "chunked basic");
    he = mkresp(buf, "200 OK", "", "5;foo=bar\r\nhello\r\n0\r\n\r\n");
    r = http_chunked_decode(buf, he, slen(buf), 0, &blen);
    CHECK(r == 0 && blen == 5 && seq(buf + he, "hello"), "chunked extension ignored");
    he = mkresp(buf, "200 OK", "", "A\r\n0123456789\r\n0\r\n\r\n");
    r = http_chunked_decode(buf, he, slen(buf), 0, &blen);
    CHECK(r == 0 && blen == 10, "chunked uppercase hex");
    he = mkresp(buf, "200 OK", "", "5 \r\nhello\r\n0\r\n\r\n");
    r = http_chunked_decode(buf, he, slen(buf), 0, &blen);
    CHECK(r == 0 && blen == 5, "chunked trailing space ok");
    he = mkresp(buf, "200 OK", "", "Z\r\nhello\r\n0\r\n\r\n");
    r = http_chunked_decode(buf, he, slen(buf), 0, &blen);
    CHECK(r == -1, "chunked bad hex refused");
    he = mkresp(buf, "200 OK", "", "5x\r\nhello\r\n0\r\n\r\n");
    r = http_chunked_decode(buf, he, slen(buf), 0, &blen);
    CHECK(r == -1, "chunked junk after size refused");
    he = mkresp(buf, "200 OK", "", "5\r\nhelloXX0\r\n\r\n");
    r = http_chunked_decode(buf, he, slen(buf), 0, &blen);
    CHECK(r == -1, "chunked missing data CRLF refused");
    he = mkresp(buf, "200 OK", "", "FFFFFFFF\r\nhello\r\n0\r\n\r\n");
    r = http_chunked_decode(buf, he, slen(buf), 0, &blen);
    CHECK(r == -1, "chunked huge size refused");
    he = mkresp(buf, "200 OK", "", "5\r\nhel");
    r = http_chunked_decode(buf, he, slen(buf), 1, &blen);
    CHECK(r == 0 && blen == 0, "chunked truncated partial keeps nothing");
    he = mkresp(buf, "200 OK", "", "5\r\nhello\r\n3\r\nab");
    r = http_chunked_decode(buf, he, slen(buf), 1, &blen);
    CHECK(r == 0 && blen == 5, "chunked truncated partial keeps complete");
    he = mkresp(buf, "200 OK", "", "5\r\nhello\r\n3\r\nab");
    r = http_chunked_decode(buf, he, slen(buf), 0, &blen);
    CHECK(r == -1, "chunked truncated non-truncated refused");
    he = mkresp(buf, "200 OK", "", "5\r\nhello\r\n0\r\nX-Trailer: v\r\n\r\n");
    r = http_chunked_decode(buf, he, slen(buf), 0, &blen);
    CHECK(r == 0 && blen == 5, "chunked trailers skipped");
    he = mkresp(buf, "200 OK", "", " 5\r\nhello\r\n0\r\n\r\n");
    r = http_chunked_decode(buf, he, slen(buf), 0, &blen);
    CHECK(r == -1, "chunked leading space refused");

    /* ---- cookies ---- */
    http_cookies_clear();
    http_cookie_store("sess=abc", 8, "example.com", "/dir/page", 0);
    CHECK(http_cookie_header("example.com", "/dir/page", 0, out, sizeof(out)) == 0 &&
          seq(out, "sess=abc"), "cookie basic send");
    /* Path boundary: /foo must not match /foobar, must match /foo/bar. */
    http_cookies_clear();
    http_cookie_store("p=1; Path=/foo", 14, "example.com", "/", 0);
    CHECK(http_cookie_header("example.com", "/foobar", 0, out, sizeof(out)) == 0 &&
          seq(out, ""), "cookie path boundary foobar refused");
    CHECK(http_cookie_header("example.com", "/foo/bar", 0, out, sizeof(out)) == 0 &&
          seq(out, "p=1"), "cookie path boundary foobar-bar ok");
    CHECK(http_cookie_header("example.com", "/foo", 0, out, sizeof(out)) == 0 &&
          seq(out, "p=1"), "cookie path equal ok");
    /* Host-only: never to a subdomain. */
    http_cookies_clear();
    http_cookie_store("h=1", 3, "example.com", "/", 0);
    CHECK(http_cookie_header("sub.example.com", "/", 0, out, sizeof(out)) == 0 &&
          seq(out, ""), "cookie host-only subdomain refused");
    CHECK(http_cookie_header("example.com", "/", 0, out, sizeof(out)) == 0 &&
          seq(out, "h=1"), "cookie host-only exact ok");
    /* Domain suffix: sent to subdomains, never planted cross-host. */
    http_cookies_clear();
    http_cookie_store("d=1; Domain=example.com", 23, "example.com", "/", 0);
    CHECK(http_cookie_header("sub.example.com", "/", 0, out, sizeof(out)) == 0 &&
          seq(out, "d=1"), "cookie domain suffix subdomain ok");
    http_cookies_clear();
    http_cookie_store("evil=1; Domain=evil.com", 23, "example.com", "/", 0);
    CHECK(http_cookie_header("example.com", "/", 0, out, sizeof(out)) == 0 &&
          seq(out, ""), "cookie foreign domain planting refused");
    http_cookies_clear();
    http_cookie_store("evil=1; Domain=ample.com", 24, "example.com", "/", 0);
    CHECK(http_cookie_header("example.com", "/", 0, out, sizeof(out)) == 0 &&
          seq(out, ""), "cookie dot-boundary planting refused");
    http_cookies_clear();
    http_cookie_store("dot=1; Domain=.example.com", 26, "example.com", "/", 0);
    CHECK(http_cookie_header("sub.example.com", "/", 0, out, sizeof(out)) == 0 &&
          seq(out, "dot=1"), "cookie leading-dot domain ok");
    /* Secure: never over plain HTTP, sent over TLS. */
    http_cookies_clear();
    http_cookie_store("s=1; Secure", 11, "example.com", "/", 1);
    CHECK(http_cookie_header("example.com", "/", 0, out, sizeof(out)) == 0 &&
          seq(out, ""), "cookie Secure not over plain HTTP");
    CHECK(http_cookie_header("example.com", "/", 1, out, sizeof(out)) == 0 &&
          seq(out, "s=1"), "cookie Secure over TLS ok");
    /* Overlong fields refused, never truncated. */
    http_cookies_clear();
    {
        static char longname[80];
        u32 i;
        for (i = 0; i < 70; i++) longname[i] = 'n';
        longname[70] = 0;
        /* name 70 chars + "=v": build via ap into a line buffer. */
        static char line[96];
        u32 pos = 0;
        ap(line, &pos, longname);
        ap(line, &pos, "=v");
        http_cookie_store(line, pos, "example.com", "/", 0);
        CHECK(http_cookie_header("example.com", "/", 0, out, sizeof(out)) == 0 &&
              seq(out, ""), "cookie overlong name refused");
    }
    http_cookies_clear();
    {
        static char line[200];
        u32 pos = 0, i;
        ap(line, &pos, "v=");
        for (i = 0; i < 140; i++) line[pos++] = 'x';
        line[pos] = 0;
        http_cookie_store(line, pos, "example.com", "/", 0);
        CHECK(http_cookie_header("example.com", "/", 0, out, sizeof(out)) == 0 &&
              seq(out, ""), "cookie overlong value refused");
    }
    /* Bad names refused. */
    http_cookies_clear();
    http_cookie_store("bad name=1", 10, "example.com", "/", 0);
    CHECK(http_cookie_header("example.com", "/", 0, out, sizeof(out)) == 0 &&
          seq(out, ""), "cookie space in name refused");
    http_cookies_clear();
    http_cookie_store("=1", 2, "example.com", "/", 0);
    CHECK(http_cookie_header("example.com", "/", 0, out, sizeof(out)) == 0 &&
          seq(out, ""), "cookie empty name refused");
    http_cookies_clear();
    http_cookie_store("noname", 6, "example.com", "/", 0);
    CHECK(http_cookie_header("example.com", "/", 0, out, sizeof(out)) == 0 &&
          seq(out, ""), "cookie no equals refused");
    /* Max-Age: 0 deletes, expiry honoured. */
    http_cookies_clear();
    http_cookie_store("d=1", 3, "example.com", "/", 0);
    http_cookie_store("d=1; Max-Age=0", 15, "example.com", "/", 0);
    CHECK(http_cookie_header("example.com", "/", 0, out, sizeof(out)) == 0 &&
          seq(out, ""), "cookie Max-Age 0 deletes");
    http_cookies_clear();
    timer_ticks = 0;
    http_cookie_store("t=1; Max-Age=1", 15, "example.com", "/", 0);
    timer_ticks = 50;
    CHECK(http_cookie_header("example.com", "/", 0, out, sizeof(out)) == 0 &&
          seq(out, "t=1"), "cookie before expiry ok");
    timer_ticks = 100;
    CHECK(http_cookie_header("example.com", "/", 0, out, sizeof(out)) == 0 &&
          seq(out, ""), "cookie at expiry gone");
    timer_ticks = 0;
    /* Jar eviction: 17 cookies, the oldest must be gone. */
    http_cookies_clear();
    {
        char nm[8];
        int k;
        for (k = 0; k < 17; k++) {
            nm[0] = 'c'; nm[1] = (char)('a' + k / 10); nm[2] = (char)('0' + k % 10);
            nm[3] = '='; nm[4] = '1'; nm[5] = 0;
            http_cookie_store(nm, 5, "example.com", "/", 0);
        }
        /* c00-style first name is ca0; after 17 inserts into a 16
           jar the oldest (ca0) must be evicted. */
        r = http_cookie_header("example.com", "/", 0, out, sizeof(out));
        CHECK(r == 0, "cookie jar 17 inserts header ok");
        /* The header must not contain ca0. */
        {
            int found = 0;
            u32 i = 0;
            while (out[i]) {
                if (out[i] == 'c' && out[i+1] == 'a' && out[i+2] == '0') found = 1;
                i++;
            }
            CHECK(!found, "cookie jar oldest evicted");
        }
    }
    /* Cookie header overflow: caller must send nothing. */
    http_cookies_clear();
    http_cookie_store("a=1", 3, "example.com", "/", 0);
    CHECK(http_cookie_header("example.com", "/", 0, out, 3) == -1,
          "cookie header overflow refused");

    /* ---- redirect resolution ---- */
    r = http_resolve_location("https://other.test/x", 1, "a.test", 443, "/",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == 0 && tls == 1 && seq(host, "other.test") && port == 443 &&
          seq(path, "/x"), "resolver absolute https ok");
    r = http_resolve_location("http://other.test/x", 1, "a.test", 443, "/",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == -1, "resolver https->http downgrade refused");
    r = http_resolve_location("https://other.test/x", 0, "a.test", 80, "/",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == 0 && tls == 1, "resolver http->https upgrade ok");
    r = http_resolve_location("http://user@evil.test/x", 0, "a.test", 80, "/",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == -1, "resolver userinfo refused");
    r = http_resolve_location("//evil.test/x", 0, "a.test", 80, "/",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == 0 && tls == 0 && seq(host, "evil.test"), "resolver scheme-relative ok");
    r = http_resolve_location("//user@evil.test/x", 0, "a.test", 80, "/",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == -1, "resolver scheme-relative userinfo refused");
    r = http_resolve_location("http://a.test:0/x", 0, "a.test", 80, "/",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == -1, "resolver port 0 refused");
    r = http_resolve_location("http://a.test:99999/x", 0, "a.test", 80, "/",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == -1, "resolver port overflow refused");
    r = http_resolve_location("http://a.test:abc/x", 0, "a.test", 80, "/",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == -1, "resolver port alpha refused");
    r = http_resolve_location("http://a.test:8080/x", 0, "a.test", 80, "/",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == 0 && port == 8080, "resolver explicit port ok");
    r = http_resolve_location("", 0, "a.test", 80, "/",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == -1, "resolver empty refused");
    r = http_resolve_location("   ", 0, "a.test", 80, "/",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == -1, "resolver blank refused");
    r = http_resolve_location("/new#frag", 0, "a.test", 80, "/old",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == 0 && seq(path, "/new"), "resolver fragment stripped");
    r = http_resolve_location("/a/b/../c", 0, "a.test", 80, "/",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == 0 && seq(path, "/a/b/../c"),
          "resolver absolute path verbatim (no collapse on absolute)");
    r = http_resolve_location("/../../etc", 0, "a.test", 80, "/",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == 0 && seq(path, "/../../etc"),
          "resolver absolute dotdot verbatim (collapse is relative-only)");
    r = http_resolve_location("sub/page", 0, "a.test", 80, "/dir/index",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == 0 && seq(path, "/dir/sub/page"), "resolver relative merge");
    r = http_resolve_location("../up", 0, "a.test", 80, "/dir/sub/index",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == 0 && seq(path, "/dir/up"), "resolver relative dotdot");
    r = http_resolve_location("../../x", 0, "a.test", 80, "/a/index",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == 0 && seq(path, "/x"), "resolver relative dotdot above root clamped");
    r = http_resolve_location("?q=1", 0, "a.test", 80, "/dir/page?old=2",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == 0 && seq(path, "/dir/page?q=1"), "resolver query-only");
    r = http_resolve_location("http://a.test", 0, "a.test", 80, "/",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == 0 && seq(path, "/"), "resolver no-path defaults to slash");
    {
        static char longhost[90];
        static char loc[110];
        u32 i, pos = 0;
        for (i = 0; i < 70; i++) longhost[i] = 'h';
        longhost[70] = 0;
        ap(loc, &pos, "http://");
        ap(loc, &pos, longhost);
        ap(loc, &pos, "/x");
        r = http_resolve_location(loc, 0, "a.test", 80, "/",
                                  &tls, host, sizeof(host), &port, path, sizeof(path),
                                  err, sizeof(err));
        CHECK(r == -1, "resolver host too long refused");
    }
    {
        static char loc[400];
        u32 i, pos = 0;
        ap(loc, &pos, "http://a.test/");
        for (i = 0; i < 300; i++) loc[pos++] = 'p';
        loc[pos] = 0;
        r = http_resolve_location(loc, 0, "a.test", 80, "/",
                                  &tls, host, sizeof(host), &port, path, sizeof(path),
                                  err, sizeof(err));
        CHECK(r == -1, "resolver path too long refused");
    }
    r = http_resolve_location("HTTPS://OTHER.TEST/X", 0, "a.test", 80, "/",
                              &tls, host, sizeof(host), &port, path, sizeof(path),
                              err, sizeof(err));
    CHECK(r == 0 && tls == 1 && seq(host, "OTHER.TEST"), "resolver uppercase scheme");

    printf("HTTP_SEC: %d PASS, %d FAIL\n", npass, nfail);
    return nfail ? 1 : 0;
}
