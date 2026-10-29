/* Host test for the Phase 4 HTTP helpers (net/http.c), in the
   style of tests/host_legacy_crypto.c: the helpers are pure
   parsing/matching, so they run standalone. The fetch wrappers
   are NOT exercised here (they need the guest TCP/TLS stack);
   they are covered by tests/qemu_test_http.py.
   Build: gcc -fno-builtin -o /tmp/host_http tests/host_http.c net/http.c
   (the -fno-builtin flag is needed because kernel/common.h
   redeclares strlen/memcpy with u32 types). */
#include <stdio.h>
#include <stdarg.h>
#include "../net/http.h"

volatile u32 timer_ticks = 0;

/* Kernel-signature string functions come from kernel/util.c
   (linked in); <string.h> is avoided because its size_t
   declarations conflict with kernel/common.h's u32 ones, as
   in the legacy host test. */
static int contains(const char *hay, const char *needle) {
    u32 hl = strlen(hay), nl = strlen(needle);
    if (nl == 0) return 1;
    if (nl > hl) return 0;
    for (u32 i = 0; i + nl <= hl; i++) {
        u32 k = 0;
        while (k < nl && hay[i + k] == needle[k]) k++;
        if (k == nl) return 1;
    }
    return 0;
}

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

static void set_body(char *dst, const char *src) {
    u32 i = 0;
    while (src[i]) { dst[i] = src[i]; i++; }
    dst[i] = 0;
}

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); fails++; } \
    else printf("ok: %s\n", msg); } while (0)

int main(void) {
    char out[256];
    u32 len;
    /* Status parsing. */
    const char *r200 = "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    u32 he = 0;
    for (u32 i = 0; i + 3 < strlen(r200); i++)
        if (!memcmp(r200 + i, "\r\n\r\n", 4)) { he = i + 4; break; }
    CHECK(http_parse_status(r200, he) == 200, "status 200");
    CHECK(http_parse_status("HTTP/1.1 302 Found\r\n\r\n", 20) == 302,
          "status 302");
    CHECK(http_parse_status("GARBAGE\r\n\r\n", 9) == -1, "status garbage");
    CHECK(http_parse_status("HTTP/1.0 abc\r\n\r\n", 14) == -1,
          "status non-numeric");
    /* Header values: case-insensitive, trimmed, first wins. */
    const char *hdrs = "HTTP/1.0 302 Found\r\nlocation:   /final  \r\n"
                       "X-A: 1\r\nx-a: 2\r\n\r\n";
    u32 hhe = (u32)strlen(hdrs);
    CHECK(http_header_value(hdrs, hhe, "Location", out, sizeof(out)) == 0 &&
          strcmp(out, "/final") == 0, "header case-insensitive + trim");
    CHECK(http_header_value(hdrs, hhe, "X-A", out, sizeof(out)) == 0 &&
          strcmp(out, "1") == 0, "header first wins");
    CHECK(http_header_value(hdrs, hhe, "Nope", out, sizeof(out)) == -1,
          "header absent");
    CHECK(http_header_value(hdrs, hhe, "Location", out, 4) == -2,
          "header truncation reported");
    /* Content-Length. */
    const char *cl1 = "HTTP/1.0 200 OK\r\nContent-Length: 42\r\n\r\n";
    CHECK(http_content_length(cl1, (u32)strlen(cl1), &len) == 0 && len == 42,
          "CL single");
    const char *cl2 = "HTTP/1.0 200 OK\r\nContent-Length: 42\r\n"
                      "content-length: 42\r\n\r\n";
    CHECK(http_content_length(cl2, (u32)strlen(cl2), &len) == 0 && len == 42,
          "CL identical duplicates");
    const char *cl3 = "HTTP/1.0 200 OK\r\nContent-Length: 42\r\n"
                      "Content-Length: 43\r\n\r\n";
    CHECK(http_content_length(cl3, (u32)strlen(cl3), &len) == -1,
          "CL conflicting duplicates refused");
    const char *cl4 = "HTTP/1.0 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n";
    CHECK(http_content_length(cl4, (u32)strlen(cl4), &len) == -1,
          "CL overflow refused");
    const char *cl5 = "HTTP/1.0 200 OK\r\nX-A: 1\r\n\r\n";
    CHECK(http_content_length(cl5, (u32)strlen(cl5), &len) == 0 &&
          len == 0xFFFFFFFFu, "CL absent");
    /* Transfer-Encoding. */
    const char *te1 = "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    CHECK(http_is_chunked(te1, (u32)strlen(te1)) == 1, "TE chunked");
    const char *te2 = "HTTP/1.0 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n";
    CHECK(http_is_chunked(te2, (u32)strlen(te2)) == 1, "TE Chunked case");
    const char *te3 = "HTTP/1.0 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n";
    CHECK(http_is_chunked(te3, (u32)strlen(te3)) == -1, "TE gzip refused");
    const char *te4 = "HTTP/1.0 200 OK\r\nX-A: 1\r\n\r\n";
    CHECK(http_is_chunked(te4, (u32)strlen(te4)) == 0, "TE absent");
    /* Chunked decoding. */
    char body[256];
    u32 bl;
    set_body(body, "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                 "5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n");
    u32 bhe = 0;
    for (u32 i = 0; i + 3 < strlen(body); i++)
        if (!memcmp(body + i, "\r\n\r\n", 4)) { bhe = i + 4; break; }
    CHECK(http_chunked_decode(body, bhe, (u32)strlen(body), 0, &bl) == 0 &&
          bl == 11 && memcmp(body + bhe, "Hello World", 11) == 0,
          "chunked basic");
    set_body(body, "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                 "5;foo=bar\r\nHello\r\n0\r\nX-Trailer: 1\r\n\r\n");
    bhe = 0;
    for (u32 i = 0; i + 3 < strlen(body); i++)
        if (!memcmp(body + i, "\r\n\r\n", 4)) { bhe = i + 4; break; }
    CHECK(http_chunked_decode(body, bhe, (u32)strlen(body), 0, &bl) == 0 &&
          bl == 5 && memcmp(body + bhe, "Hello", 5) == 0,
          "chunked extensions + trailers");
    set_body(body, "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                 "ZZ\r\nHello\r\n0\r\n\r\n");
    bhe = 0;
    for (u32 i = 0; i + 3 < strlen(body); i++)
        if (!memcmp(body + i, "\r\n\r\n", 4)) { bhe = i + 4; break; }
    CHECK(http_chunked_decode(body, bhe, (u32)strlen(body), 0, &bl) == -1,
          "chunked bad hex refused");
    set_body(body, "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                 "A\r\nabc");
    bhe = 0;
    for (u32 i = 0; i + 3 < strlen(body); i++)
        if (!memcmp(body + i, "\r\n\r\n", 4)) { bhe = i + 4; break; }
    CHECK(http_chunked_decode(body, bhe, (u32)strlen(body), 0, &bl) == -1,
          "chunked truncated body refused on clean close");
    set_body(body, "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                 "5\r\nHel");
    bhe = 0;
    for (u32 i = 0; i + 3 < strlen(body); i++)
        if (!memcmp(body + i, "\r\n\r\n", 4)) { bhe = i + 4; break; }
    CHECK(http_chunked_decode(body, bhe, (u32)strlen(body), 1, &bl) == 0 &&
          bl == 0, "chunked truncated-buffer partial (no complete chunk)");
    /* Cookies. */
    http_cookies_clear();
    http_cookie_store("sess=abc; Path=/; Max-Age=3600",
                      strlen("sess=abc; Path=/; Max-Age=3600"),
                      "a.test", "/set", 0);
    CHECK(http_cookie_header("a.test", "/check", 0, out, sizeof(out)) == 0 &&
          strcmp(out, "sess=abc") == 0, "cookie send-back");
    CHECK(http_cookie_header("b.test", "/check", 0, out, sizeof(out)) == 0 &&
          out[0] == 0, "cookie host scoping");
    http_cookie_store("sec=1; Secure", strlen("sec=1; Secure"),
                      "a.test", "/set", 1);
    CHECK(http_cookie_header("a.test", "/check", 0, out, sizeof(out)) == 0 &&
          strcmp(out, "sess=abc") == 0, "Secure not sent over plain HTTP");
    CHECK(http_cookie_header("a.test", "/check", 1, out, sizeof(out)) == 0 &&
          contains(out, "sec=1") != 0, "Secure sent over TLS");
    http_cookie_store("p=1; Path=/dir", strlen("p=1; Path=/dir"),
                      "a.test", "/set", 0);
    CHECK(http_cookie_header("a.test", "/dir/x", 0, out, sizeof(out)) == 0 &&
          contains(out, "p=1") != 0, "cookie path prefix match");
    CHECK(http_cookie_header("a.test", "/other", 0, out, sizeof(out)) == 0 &&
          contains(out, "p=1") == 0, "cookie path mismatch");
    http_cookie_store("x=1; Domain=other.test",
                      strlen("x=1; Domain=other.test"), "a.test", "/set", 0);
    CHECK(http_cookie_header("a.test", "/check", 0, out, sizeof(out)) == 0 &&
          contains(out, "x=1") == 0, "foreign Domain refused");
    http_cookie_store("d=1; Domain=.test", strlen("d=1; Domain=.test"),
                      "a.test", "/set", 0);
    CHECK(http_cookie_header("b.test", "/check", 0, out, sizeof(out)) == 0 &&
          contains(out, "d=1") != 0, "suffix Domain match");
    http_cookie_store("sess=; Max-Age=0", strlen("sess=; Max-Age=0"),
                      "a.test", "/set", 0);
    CHECK(http_cookie_header("a.test", "/check", 0, out, sizeof(out)) == 0 &&
          contains(out, "sess=") == 0, "Max-Age=0 deletes");
    http_cookie_store("t=1; Max-Age=1", strlen("t=1; Max-Age=1"),
                      "a.test", "/set", 0);
    timer_ticks = 50;
    CHECK(http_cookie_header("a.test", "/check", 0, out, sizeof(out)) == 0 &&
          contains(out, "t=1") != 0, "Max-Age not yet expired");
    timer_ticks = 150;
    CHECK(http_cookie_header("a.test", "/check", 0, out, sizeof(out)) == 0 &&
          contains(out, "t=1") == 0, "Max-Age expiry respected");
    char big[256];
    big[0] = 'b'; big[1] = 'i'; big[2] = 'g'; big[3] = '=';
    for (int i = 0; i < 199; i++) big[4 + i] = 'a';
    big[203] = 0;
    http_cookie_store(big, strlen(big), "a.test", "/set", 0);
    CHECK(http_cookie_header("a.test", "/check", 0, out, sizeof(out)) == 0 &&
          contains(out, "big=") == 0, "overlong cookie value refused");
    CHECK(http_cookie_header("a.test", "/check", 0, out, 3) == -1,
          "cookie header overflow reported");
    /* Location resolution. */
    int tls; char nh[64]; u16 np; char npth[128]; char err[96];
    CHECK(http_resolve_location("https://b.test:8443/final", 0, "a.test", 80,
                                "/old", &tls, nh, sizeof(nh), &np, npth,
                                sizeof(npth), err, sizeof(err)) == 0 &&
          tls == 1 && strcmp(nh, "b.test") == 0 && np == 8443 &&
          strcmp(npth, "/final") == 0, "absolute URL");
    CHECK(http_resolve_location("http://b.test/final", 1, "a.test", 443,
                                "/old", &tls, nh, sizeof(nh), &np, npth,
                                sizeof(npth), err, sizeof(err)) == -1 &&
          contains(err, "downgrade") != 0, "https->http downgrade refused");
    CHECK(http_resolve_location("new", 0, "a.test", 80, "/dir/old",
                                &tls, nh, sizeof(nh), &np, npth,
                                sizeof(npth), err, sizeof(err)) == 0 &&
          strcmp(npth, "/dir/new") == 0, "relative merge");
    CHECK(http_resolve_location("../up", 0, "a.test", 80, "/a/b/c",
                                &tls, nh, sizeof(nh), &np, npth,
                                sizeof(npth), err, sizeof(err)) == 0 &&
          strcmp(npth, "/a/up") == 0, "dot-dot collapse");
    CHECK(http_resolve_location("//other.test/x", 1, "a.test", 443, "/old",
                                &tls, nh, sizeof(nh), &np, npth,
                                sizeof(npth), err, sizeof(err)) == 0 &&
          tls == 1 && strcmp(nh, "other.test") == 0 && np == 443,
          "scheme-relative keeps scheme");
    CHECK(http_resolve_location("/abs#frag", 0, "a.test", 80, "/old",
                                &tls, nh, sizeof(nh), &np, npth,
                                sizeof(npth), err, sizeof(err)) == 0 &&
          strcmp(npth, "/abs") == 0, "fragment stripped");
    CHECK(http_resolve_location("http://u@b.test/", 0, "a.test", 80, "/old",
                                &tls, nh, sizeof(nh), &np, npth,
                                sizeof(npth), err, sizeof(err)) == -1,
          "userinfo refused");
    CHECK(http_resolve_location("http://b.test:99999/", 0, "a.test", 80,
                                "/old", &tls, nh, sizeof(nh), &np, npth,
                                sizeof(npth), err, sizeof(err)) == -1,
          "bad port refused");
    printf(fails ? "HOST_HTTP: %d FAILURES\n" : "HOST_HTTP: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
