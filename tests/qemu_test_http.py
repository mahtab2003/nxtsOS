#!/usr/bin/env python3
"""web/SSL Phase 4 test: HTTP layer (redirects, cookies, chunked
transfer encoding, header polish).

Boots (guest runs `dhcp` first). Port 12355 so this suite can
run alongside the castore (12352), tls13 (12353) and legacy
(12354) suites. Plain-HTTP boots use PlainPeer (a NetPeer
subclass speaking raw HTTP on guest TCP port 80); HTTPS boots
use SslPeer with raw_routes (full response bytes per path) and
request recording; the legacy-target boot uses DualPeer (an
SslPeer subclass: connection 0 serves a redirect, connection 1
records the ClientHello and answers with a fatal alert).

Plain boots (host a.test; DNS answers every query with the
peer IP, so other.test also reaches the peer):
  redirect:      /redir 302 -> /final, final body fetched.
  multi:         /r1 -> /r2 -> /r3 -> /final (3 hops).
  loop:          /loop 302 -> /loop: "redirect loop detected",
                 peer saw exactly 1 request (refused before
                 re-fetching).
  limit:         /c1 -> ... -> /c6 -> /final (6 redirects):
                 "redirect limit reached", 6 requests, /final
                 never requested.
  crosshost:     /xhost 302 -> http://other.test/xhosted:
                 marker + Host: other.test on hop 2.
  relative:      /dir/old 302 -> "new": /dir/new fetched.
  cookie-main:   /set (Set-Cookie sess), /check sends it back,
                 `cookies list` shows it, `cookies clear`,
                 `net cookies list` shows the empty jar,
                 /check2 sends nothing.
  cookie-edge:   Secure not sent over plain HTTP; Path
                 scoping (/dir/ok yes, /other no); foreign
                 Domain refused; Max-Age=0 deletes.
  chunked:       two chunks + trailer -> "Hello World".
  chunkext:      chunk extensions + trailers -> decoded.
  chunkbad:      malformed chunk size -> "http: failed".
  chunktrunc:    declared 10 bytes, sent 3, closed -> failed.
  header-case:   lowercase "location:" + lowercase
                 "content-length:" -> final body fetched.
  dupcl:         conflicting duplicate Content-Length -> failed.
  bigheader:     header block over 4096 bytes -> failed.
  noredirect:    --no-redirect: "redirect not followed:
                 /final", 1 request.
  nocookies:     --no-cookies on the setting fetch: nothing
                 stored, later fetch sends nothing.
  flag-order:    --no-cookies --no-redirect together: redirect
                 not followed.
HTTPS boots (host http.test, TOFU):
  https-redirect:  /redir 302 -> /hfinal, body fetched.
  https-cookie:    /hset sets hs, /hcheck sends it back.
  https-chunked:   chunked body over TLS -> decoded.
  https-crosshost: /hxhost 302 -> https://other.test/xhosted
                 (the leaf's SAN covers both hosts, so the
                 hostname check passes on hop 2).
  https-downgrade: /hdown 302 -> http://...: "redirect
                   refused: https to http downgrade", peer saw
                   1 request, no plain fetch attempted.
  https-legacy-target: /hleg 302 -> https://http.test/legacy:
                   hop 2 MUST attempt a modern handshake (its
                   ClientHello version is 0x0303 offering
                   0x1301, not legacy-only 0x002F) and then fail
                   (fatal alert) with "redirect target fetch
                   failed" and no body — proving the legacy flag
                   is never carried across a redirect.

Usage: python3 tests/qemu_test_http.py <iso> <workdir>
<workdir> is created by tests/qemu_test_http_setup.py.
"""
import os
import shutil
import ssl
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tls_peer_lib as lib

ISO = sys.argv[1]
WORK = sys.argv[2]
PORT = 12355


def resp(status, headers, body):
    out = f"HTTP/1.0 {status}\r\n".encode()
    for k, v in headers:
        out += f"{k}: {v}\r\n".encode()
    out += b"\r\n" + body
    return out


def redir(loc):
    return resp("302 Found", [("Location", loc), ("Content-Length", "0")], b"")


PLAIN_ROUTES = {
    "/redir": redir("/final"),
    "/final": resp("200 OK", [("content-length", "15")], b"HTTP-FINAL-BODY"),
    "/r1": redir("/r2"),
    "/r2": redir("/r3"),
    "/r3": redir("/final"),
    "/loop": redir("/loop"),
    "/c1": redir("/c2"),
    "/c2": redir("/c3"),
    "/c3": redir("/c4"),
    "/c4": redir("/c5"),
    "/c5": redir("/c6"),
    "/c6": redir("/final"),
    "/xhost": redir("http://other.test/xhosted"),
    "/xhosted": resp("200 OK", [("Content-Length", "8")], b"XHOST-OK"),
    "/dir/old": redir("new"),
    "/dir/new": resp("200 OK", [("Content-Length", "6")], b"REL-OK"),
    "/set": resp("200 OK", [("Set-Cookie", "sess=abc; Path=/"),
                            ("Content-Length", "6")], b"SET-OK"),
    "/check": resp("200 OK", [("Content-Length", "8")], b"CHECK-OK"),
    "/check2": resp("200 OK", [("Content-Length", "9")], b"CHECK2-OK"),
    "/check3": resp("200 OK", [("Content-Length", "9")], b"CHECK3-OK"),
    "/setsecure": resp("200 OK", [("Set-Cookie", "sec=1; Secure; Path=/"),
                                   ("Content-Length", "9")], b"SETSEC-OK"),
    "/setpath": resp("200 OK", [("Set-Cookie", "p=1; Path=/dir"),
                                 ("Content-Length", "10")], b"SETPATH-OK"),
    "/dir/ok": resp("200 OK", [("Content-Length", "6")], b"DIR-OK"),
    "/other": resp("200 OK", [("Content-Length", "8")], b"OTHER-OK"),
    "/setbad": resp("200 OK", [("Set-Cookie", "x=1; Domain=other.test"),
                                ("Content-Length", "9")], b"SETBAD-OK"),
    "/setdel": resp("200 OK", [("Set-Cookie", "sess=; Max-Age=0"),
                                ("Content-Length", "9")], b"SETDEL-OK"),
    "/chunked": (b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                 b"6\r\nHello \r\n5\r\nWorld\r\n0\r\nX-Trailer: 1\r\n\r\n"),
    "/chunkext": (b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                  b"6;foo=bar\r\nEXT-OK\r\n0\r\n\r\n"),
    "/chunkbad": (b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                  b"ZZ\r\nHello\r\n0\r\n\r\n"),
    "/chunktrunc": (b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                    b"A\r\nabc"),
    "/case": resp("302 found", [("location", "/final"),
                                ("content-length", "0")], b""),
    "/dupcl": (b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n"
               b"Content-Length: 6\r\n\r\nHELLO!"),
    "/bigheader": (b"HTTP/1.0 200 OK\r\nX-Pad: " + b"a" * 5000 +
                   b"\r\nContent-Length: 4\r\n\r\nBODY"),
    "/ua": resp("200 OK", [("Content-Length", "5")], b"UA-OK"),
}

HTTPS_RAW = {
    "/redir": redir("/hfinal"),
    "/hset": resp("200 OK", [("Set-Cookie", "hs=1; Path=/"),
                             ("Content-Length", "7")], b"HSET-OK"),
    "/hchunk": (b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"6\r\nHello \r\n5\r\nWorld\r\n0\r\n\r\n"),
    "/hxhost": redir("https://other.test/xhosted"),
    "/hdown": redir("http://http.test/hfinal"),
    "/hleg": redir("https://http.test/legacy"),
}
HTTPS_ROUTES = {
    "/hfinal": b"HTTPS-FINAL",
    "/hcheck": b"HCHECK-OK",
    "/xhosted": b"XH-OK",
}


class PlainPeer(lib.NetPeer):
    """Raw HTTP peer on guest TCP port 80. routes maps a path
    to the complete response bytes. requests records
    (path, raw request) per connection, in order."""

    def __init__(self, routes, listen_port):
        self.routes = routes
        self.requests = []
        self.table = set(routes)
        super().__init__(listen_port, tcp_port=80)

    def tls_reset(self):
        self.app_buf = b""
        self.responded = False

    def tls_feed(self, src_mac, data):
        self.app_buf += data
        if b"\r\n\r\n" in self.app_buf and not self.responded:
            line = self.app_buf.split(b"\r\n", 1)[0].decode("latin1")
            parts = line.split(" ")
            path = parts[1] if len(parts) >= 2 else "/"
            self.requests.append((path, bytes(self.app_buf)))
            resp_bytes = self.routes.get(
                path, b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            self.log(f"PLAIN> serving {path} -> {len(resp_bytes)} bytes")
            self.send_queue += resp_bytes
            self.responded = True
            # Close after the response: the guest's chunked
            # reader needs the FIN (no Content-Length to stop
            # on), and close-delimited readers stop at FIN too.
            self.fin_pending = True
            self.maybe_send(src_mac)


class DualPeer(lib.SslPeer):
    """Connection 0 behaves as SslPeer (serves the redirect);
    later connections record the ClientHello and answer with a
    fatal alert, so the test can prove hop 2 attempted a modern
    handshake (not a legacy one) and then failed."""

    def __init__(self, chain_files, routes, raw_routes, listen_port):
        super().__init__(chain_files, routes, listen_port,
                         raw_routes=raw_routes)
        self.hellos = []
        self.refuse = False

    def tls_new_connection(self):
        if self.conn_count >= 1:
            self.refuse = True
            self.conn_count += 1
            self.sslobj = None
            self.ssl_in = None
            self.ssl_out = None
            self.ssl_done = False
            self.app_buf = b""
            self.responded = False
            self.neg_recorded = False
        else:
            self.refuse = False
            super().tls_new_connection()

    def tls_feed(self, src_mac, data):
        if not self.refuse:
            super().tls_feed(src_mac, data)
            return
        self.app_buf += data
        if self.responded or len(self.app_buf) < 5:
            return
        reclen = (self.app_buf[3] << 8) | self.app_buf[4]
        if len(self.app_buf) < 5 + reclen:
            return  # ClientHello still arriving in segments
        self.hellos.append(bytes(self.app_buf[:5 + reclen]))
        self.send_queue += b"\x15\x03\x03\x00\x02\x02\x28"
        self.responded = True
        self.fin_pending = True
        self.maybe_send(src_mac)


def parse_hello(data):
    """Return (client_version, [suites]) for a ClientHello."""
    assert data[0] == 0x16, "not a handshake record"
    hs = data[5:]
    assert hs[0] == 0x01, "not a ClientHello"
    version = (hs[4] << 8) | hs[5]
    sess_len = hs[6 + 32]
    off = 6 + 32 + 1 + sess_len
    suites_len = (hs[off] << 8) | hs[off + 1]
    suites = []
    for i in range(0, suites_len, 2):
        suites.append((hs[off + 2 + i] << 8) | hs[off + 3 + i])
    return version, suites


def run_boot(tag, make_peer, script):
    serial = os.path.join(WORK, f"http-{tag}-serial.log")
    mon = os.path.join(WORK, f"http-{tag}-mon.sock")
    for p in (serial, mon):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
    qemu = lib.start_qemu(ISO, serial, mon, None, listen_port=PORT)
    peer = None
    ok = True
    try:
        peer = make_peer()
        threading.Thread(target=peer.run, daemon=True).start()
        ok &= lib.wait_mon(mon)
        ok &= lib.wait_prompt(serial, "root@nxts> ", 60)
        s = lib.connect_mon(mon)

        def send_text(txt):
            def type_cmd(t):
                for ch in t:
                    s.sendall(f"sendkey {lib.KEYMAP_REPO.get(ch, ch)}\n".encode())
                    time.sleep(0.15)
                s.sendall(b"sendkey ret\n")
                time.sleep(1)

            # Echo check that actually works: `before` is taken
            # AFTER the prompt was printed, so the fresh slice
            # starts mid-line and can never contain
            # "root@nxts> <cmd>". Match the command text plus its
            # newline instead (exact: a doubled sendkey letter
            # breaks the "\n" adjacency, so a mistype still
            # retries instead of false-matching).
            before = len(lib.log_text(serial))
            type_cmd(txt)
            for _ in range(150):
                fresh = lib.log_text(serial)[before:]
                if txt + "\n" in fresh and fresh.count("root@nxts> ") >= 1:
                    return
                time.sleep(0.1)
            if txt + "\n" not in lib.log_text(serial)[before:]:
                before2 = len(lib.log_text(serial))
                type_cmd(txt)
                for _ in range(150):
                    if txt + "\n" in lib.log_text(serial)[before2:]:
                        break
                    time.sleep(0.1)

        send_text("dhcp")
        for cmd, marker, timeout in script:
            send_text(cmd)
            if marker:
                ok &= lib.wait_for(serial, lambda t, m=marker: m in t,
                                   timeout, f"{tag} {marker}")
        time.sleep(1)
        s.close()
    finally:
        if peer is not None:
            peer.running = False
        qemu.terminate()
        try:
            qemu.wait(timeout=10)
        except subprocess.TimeoutExpired:
            qemu.kill()
    log = lib.log_text(serial)
    for m in ("EXCEPTION", "PANIC", "page fault"):
        if m in log:
            print(f"  {tag}: FORBIDDEN marker present: {m}")
            ok = False
    for e in getattr(peer, "ssl_errors", []) + getattr(peer, "errors", []):
        print(f"  {tag}: peer error: {e}")
        ok = False
    return ok, log, peer


def reqs(peer):
    # Request log filtered to KNOWN routes (paths the peer
    # serves). A QEMU sendkey doubling occasionally mistypes a
    # command ("/seet", "//redir", "/hchunkk"); the guest then
    # fetches an unknown path, gets a 404, and the harness
    # retry runs the correct command — but the spurious 404
    # request would otherwise break exact-count assertions.
    # Filtering it is sound, not a weakening: every real
    # redirect/cookie bug changes the KNOWN-path sequence
    # (a missing expected path, a repeated path, or an extra
    # known hop), and those still fail. Only unknown-path
    # 404 noise is removed.
    t = getattr(peer, "table", None)
    if t is None:
        return [(p, r) for p, r in peer.requests]
    return [(p, r) for p, r in peer.requests if p in t]


def has_hdr(requests, idx, needle):
    return needle.encode() in requests[idx][1]


def check(tag, ok, log, peer, fn):
    if fn is not None:
        try:
            ok = fn(log, peer) and ok
        except Exception as e:
            print(f"  {tag}: assertion raised {e!r}")
            ok = False
    print(f"  {tag}: {'PASS' if ok else 'FAIL'}")
    return ok


def plain_peer():
    return PlainPeer(PLAIN_ROUTES, PORT)


def ssl_peer():
    return lib.SslPeer([(f"{WORK}/chain-http.pem", f"{WORK}/http-leaf-key.pem")],
                       HTTPS_ROUTES, PORT, raw_routes=HTTPS_RAW)


def dual_peer():
    return DualPeer([(f"{WORK}/chain-http.pem", f"{WORK}/http-leaf-key.pem")],
                    HTTPS_ROUTES, HTTPS_RAW, PORT)


def main():
    boots = [
        ("redirect", plain_peer, [("http a.test /redir", "HTTP-FINAL-BODY", 60)],
         lambda log, p: (
             [x[0] for x in reqs(p)] == ["/redir", "/final"] and
             has_hdr(reqs(p), 0, "User-Agent: nxtsOS") and
             has_hdr(reqs(p), 0, "Accept: */*") and
             has_hdr(reqs(p), 0, "Connection: close"))),
        ("multi", plain_peer, [("http a.test /r1", "HTTP-FINAL-BODY", 60)],
         lambda log, p: [x[0] for x in reqs(p)] ==
         ["/r1", "/r2", "/r3", "/final"]),
        ("loop", plain_peer, [("http a.test /loop", "redirect loop", 60)],
         lambda log, p: len(reqs(p)) == 1),
        ("limit", plain_peer, [("http a.test /c1", "redirect limit", 60)],
         lambda log, p: [x[0] for x in reqs(p)] ==
         ["/c1", "/c2", "/c3", "/c4", "/c5", "/c6"]),
        ("crosshost", plain_peer, [("http a.test /xhost", "XHOST-OK", 60)],
         lambda log, p: [x[0] for x in reqs(p)] == ["/xhost", "/xhosted"] and
         has_hdr(reqs(p), 1, "Host: other.test")),
        ("relative", plain_peer, [("http a.test /dir/old", "REL-OK", 60)],
         lambda log, p: [x[0] for x in reqs(p)] == ["/dir/old", "/dir/new"]),
        ("cookie-main", plain_peer, [
            ("http a.test /set", "SET-OK", 60),
            ("http a.test /check", "CHECK-OK", 60),
            ("cookies list", "sess=abc", 30),
            ("cookies clear", "cookies cleared: 1", 30),
            ("net cookies list", "(no cookies stored)", 30),
            ("http a.test /check2", "CHECK2-OK", 60)],
         lambda log, p: (
             [x[0] for x in reqs(p)] == ["/set", "/check", "/check2"] and
             has_hdr(reqs(p), 1, "Cookie: sess=abc") and
             not has_hdr(reqs(p), 2, "Cookie:"))),
        ("cookie-edge", plain_peer, [
            ("http a.test /setsecure", "SETSEC-OK", 60),
            ("http a.test /check", "CHECK-OK", 60),
            ("http a.test /setpath", "SETPATH-OK", 60),
            ("http a.test /dir/ok", "DIR-OK", 60),
            ("http a.test /other", "OTHER-OK", 60),
            ("http a.test /setbad", "SETBAD-OK", 60),
            ("http a.test /check2", "CHECK2-OK", 60),
            ("http a.test /set", "SET-OK", 60),
            ("http a.test /setdel", "SETDEL-OK", 60),
            ("http a.test /check3", "CHECK3-OK", 60)],
         lambda log, p: (
             [x[0] for x in reqs(p)] == ["/setsecure", "/check", "/setpath",
                                         "/dir/ok", "/other", "/setbad",
                                         "/check2", "/set", "/setdel",
                                         "/check3"] and
             not has_hdr(reqs(p), 1, "sec=") and
             has_hdr(reqs(p), 3, "Cookie: p=1") and
             not has_hdr(reqs(p), 3, "sec=") and
             not has_hdr(reqs(p), 4, "Cookie:") and
             not has_hdr(reqs(p), 6, "x=1") and
             not has_hdr(reqs(p), 9, "sess="))),
        ("chunked", plain_peer, [
            ("http a.test /chunked", "Hello World", 60),
            ("http a.test /chunkext", "EXT-OK", 60)],
         lambda log, p: [x[0] for x in reqs(p)] == ["/chunked", "/chunkext"]),
        ("chunkbad", plain_peer, [("http a.test /chunkbad", "http: failed", 60)],
         lambda log, p: len(reqs(p)) == 1),
        ("chunktrunc", plain_peer,
         [("http a.test /chunktrunc", "http: failed", 60)],
         lambda log, p: len(reqs(p)) == 1),
        ("header-case", plain_peer,
         [("http a.test /case", "HTTP-FINAL-BODY", 60)],
         lambda log, p: [x[0] for x in reqs(p)] == ["/case", "/final"]),
        ("dupcl", plain_peer, [("http a.test /dupcl", "http: failed", 60)],
         lambda log, p: len(reqs(p)) == 1),
        ("bigheader", plain_peer,
         [("http a.test /bigheader", "http: failed", 60)],
         lambda log, p: len(reqs(p)) == 1),
        ("noredirect", plain_peer,
         [("http --no-redirect a.test /redir",
           "redirect not followed: /final", 60)],
         lambda log, p: len(reqs(p)) == 1),
        ("nocookies", plain_peer, [
            ("http --no-cookies a.test /set", "SET-OK", 60),
            ("http a.test /check", "CHECK-OK", 60)],
         lambda log, p: [x[0] for x in reqs(p)] == ["/set", "/check"] and
         not has_hdr(reqs(p), 1, "Cookie:")),
        ("flag-order", plain_peer,
         [("http --no-cookies --no-redirect a.test /redir",
           "redirect not followed: /final", 60)],
         lambda log, p: len(reqs(p)) == 1),
        ("https-redirect", ssl_peer,
         [("https http.test /redir", "HTTPS-FINAL", 60)],
         lambda log, p: [x[0] for x in reqs(p)] == ["/redir", "/hfinal"]),
        ("https-cookie", ssl_peer, [
            ("https http.test /hset", "HSET-OK", 60),
            ("https http.test /hcheck", "HCHECK-OK", 60)],
         lambda log, p: [x[0] for x in reqs(p)] == ["/hset", "/hcheck"] and
         has_hdr(reqs(p), 1, "Cookie: hs=1")),
        ("https-chunked", ssl_peer,
         [("https http.test /hchunk", "Hello World", 60)],
         lambda log, p: len(reqs(p)) == 1),
        ("https-crosshost", ssl_peer,
         [("https http.test /hxhost", "XH-OK", 60)],
         lambda log, p: [x[0] for x in reqs(p)] == ["/hxhost", "/xhosted"] and
         has_hdr(reqs(p), 1, "Host: other.test")),
        ("https-downgrade", ssl_peer,
         [("https http.test /hdown", "downgrade", 60)],
         lambda log, p: len(reqs(p)) == 1 and "HTTPS-FINAL" not in log),
        ("https-legacy-target", dual_peer,
         [("https http.test /hleg", "redirect target fetch failed", 60)],
         lambda log, p: (
             len(reqs(p)) == 1 and len(p.hellos) == 1 and
             parse_hello(p.hellos[0])[0] == 0x0303 and
             0x1301 in parse_hello(p.hellos[0])[1] and
             parse_hello(p.hellos[0])[1] != [0x002F] and
             "LEGACY-BODY" not in log)),
    ]
    allok = True
    for tag, make_peer, script, fn in boots:
        ok, log, peer = run_boot(tag, make_peer, script)
        allok = check(tag, ok, log, peer, fn) and allok
    print("SUITE http " + ("PASS" if allok else "FAIL"))
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())
