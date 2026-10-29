#ifndef NXTS_HTTP_H
#define NXTS_HTTP_H
#include "../kernel/common.h"

/* nxtsOS HTTP layer (web/SSL Phase 4). Two levels, deliberately:
   - Single-request cores (net_http_get / net_https_get* and the
     *_single variants in net.h) fetch exactly one response: no
     redirects, no cookies. The package repo and castore update
     call those, and they must take no part in redirect/cookie
     behaviour changes.
   - Redirect + cookie wrappers (net_http_fetch /
     net_https_fetch) used by the shell fetch commands and the
     Web window. They never weaken the TLS policy: no
     https->http downgrade, no legacy carried across a
     redirect, cert refusal on any hop propagates. */

#define HTTP_FETCH_FOLLOW_REDIRECT 1
#define HTTP_FETCH_USE_COOKIES 2

#define HTTP_MAX_HEADER 4096

/* Wrappers. Returns the final body length, -2 on certificate
   refusal (any hop), -4 when a redirect was met but following
   is disabled, or -1. On a policy refusal, the reason is in
   net_http_fetch_error(). The legacy single-use flag (if armed
   by the caller) is consumed by hop 1 only; later hops are
   modern by construction. */
int net_http_fetch(const char *host, u16 port, const char *path,
                   char *buf, u32 max, int flags);
int net_https_fetch(int mode, const char *host, u16 port, const char *path,
                    char *buf, u32 max, int flags);
const char *net_http_fetch_error(void);

/* Response parsing helpers (shared by both cores; also the
   host-test surface). buf holds the raw stream; header_end is
   the offset just past the blank line ending the headers. */
int http_parse_status(const char *buf, u32 header_end); /* code, or -1 */
/* 0 found (value copied, NUL-terminated), -1 absent, -2 value
   did not fit out_max (caller must treat as absent). First
   matching header wins; names match case-insensitively. */
int http_header_value(const char *buf, u32 header_end, const char *name,
                      char *out, u32 out_max);
/* 0 ok; *len_out is the length, or 0xFFFFFFFF when absent.
   -1 on conflicting duplicate values or overflow. */
int http_content_length(const char *buf, u32 header_end, u32 *len_out);
/* 1 Transfer-Encoding is exactly "chunked", 0 no such header,
   -1 any other encoding (refused). */
int http_is_chunked(const char *buf, u32 header_end);
/* Decode a chunked body in place (decoded length <= encoded
   length, so the forward copy is safe). total is the stored
   stream length; truncated says the caller's buffer cut the
   stream (partial decode then keeps what is complete and still
   returns 0). Returns 0 ok (*body_len_out set) or -1 on a
   malformed body. */
int http_chunked_decode(char *buf, u32 header_end, u32 total,
                        int truncated, u32 *body_len_out);
/* Store every Set-Cookie line in the header block. */
void http_store_all_cookies(const char *buf, u32 header_end,
                            const char *host, const char *path, int is_tls);

/* Cookie jar (memory-only; cleared on reboot). line/len is one
   Set-Cookie header value (no trailing CRLF). */
void http_cookie_store(const char *line, u32 len, const char *host,
                       const char *path, int is_tls);
/* Build "name=value; ..." for a request, or "" when nothing
   matches. Returns 0 ok, -1 if the header would not fit
   out_max (caller must send no Cookie header at all then). */
int http_cookie_header(const char *host, const char *path, int is_tls,
                       char *out, u32 out_max);
void http_cookies_list(void);
int http_cookies_clear(void);

/* Resolve a Location value against the current request.
   Returns 0 ok, or -1 with the reason in err_out (including
   the https->http downgrade refusal). Host/path outputs are
   bounded by host_max/path_max (including the NUL). */
int http_resolve_location(const char *loc, int cur_tls,
                          const char *cur_host, u16 cur_port,
                          const char *cur_path,
                          int *tls_out, char *host_out, u32 host_max,
                          u16 *port_out, char *path_out, u32 path_max,
                          char *err_out, u32 err_max);

#endif
