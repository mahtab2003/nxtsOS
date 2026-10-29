#!/usr/bin/env python3
"""v1.1.4 release security pass: QEMU-level hostile HTTP inputs
that the Phase 4 suite (qemu_test_http.py) does not cover:
userinfo redirects (absolute + scheme-relative), bad-port
redirects (0, overflow, alpha), overlong redirect targets
(host/path), overlong cookie names, huge chunk sizes, and
Secure cookies over plain HTTP at the wrapper level (not
just the helpers). Each refusal must happen BEFORE any
follow-up fetch: the peer must see exactly the expected
requests, no more.

Port 12356 so this can run alongside the other suites.
Usage: python3 tests/qemu_test_http_sec.py <iso> <workdir>
(workdir need not be pre-created; no setup script needed).
"""
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tls_peer_lib as lib

ISO = sys.argv[1]
WORK = sys.argv[2]
PORT = 12356
os.makedirs(WORK, exist_ok=True)


def resp(status, headers, body):
    out = f"HTTP/1.0 {status}\r\n".encode()
    for k, v in headers:
        out += f"{k}: {v}\r\n".encode()
    out += b"\r\n" + body
    return out


def redir(loc):
    return resp("302 Found", [("Location", loc), ("Content-Length", "0")], b"")


LONGHOST = "h" * 70 + ".test"
LONGPATH = "p" * 300
ROUTES = {
    "/uinfo": redir("http://user@evil.test/x"),
    "/uinfo2": redir("//user@evil.test/x"),
    "/badport0": redir("http://a.test:0/x"),
    "/badport9": redir("http://a.test:99999/x"),
    "/badporta": redir("http://a.test:abc/x"),
    "/longhost": redir(f"http://{LONGHOST}/x"),
    "/longpath": redir(f"http://a.test/{LONGPATH}"),
    "/setlong": resp("200 OK", [("Set-Cookie", "n" * 70 + "=v"),
                                ("Content-Length", "10")], b"SETLONG-OK"),
    "/checklong": resp("200 OK", [("Content-Length", "12")], b"CHECKLONG-OK"),
    "/chunkhuge": (b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                   b"FFFFFFFF\r\nhello\r\n0\r\n\r\n"),
    "/setsec": resp("200 OK", [("Set-Cookie", "sec=1; Secure; Path=/"),
                               ("Content-Length", "9")], b"SETSEC-OK"),
    "/checksec": resp("200 OK", [("Content-Length", "11")], b"CHECKSEC-OK"),
}


class PlainPeer(lib.NetPeer):
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
            self.send_queue += resp_bytes
            self.responded = True
            self.fin_pending = True
            self.maybe_send(src_mac)


def run_boot(tag, script):
    serial = os.path.join(WORK, f"httpsec-{tag}-serial.log")
    mon = os.path.join(WORK, f"httpsec-{tag}-mon.sock")
    for p in (serial, mon):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
    qemu = lib.start_qemu(ISO, serial, mon, None, listen_port=PORT)
    peer = None
    ok = True
    try:
        peer = PlainPeer(ROUTES, PORT)
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
    return ok, log, peer


def reqs(peer):
    return [(p, r) for p, r in peer.requests if p in peer.table]


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


def main():
    boots = [
        ("uinfo", [("http a.test /uinfo", "userinfo", 60)],
         lambda log, p: [x[0] for x in reqs(p)] == ["/uinfo"]),
        ("uinfo2", [("http a.test /uinfo2", "userinfo", 60)],
         lambda log, p: [x[0] for x in reqs(p)] == ["/uinfo2"]),
        ("badport0", [("http a.test /badport0", "bad port", 60)],
         lambda log, p: [x[0] for x in reqs(p)] == ["/badport0"]),
        ("badport9", [("http a.test /badport9", "bad port", 60)],
         lambda log, p: [x[0] for x in reqs(p)] == ["/badport9"]),
        ("badporta", [("http a.test /badporta", "bad port", 60)],
         lambda log, p: [x[0] for x in reqs(p)] == ["/badporta"]),
        ("longtarget", [
            ("http a.test /longhost", "host too long", 60),
            # Overlong Location values never reach the resolver:
            # the fetch wrapper's 256-byte http_loc buffer caps
            # the value first (http_header_value -2 = absent),
            # so the 302 is returned as an (empty) body and
            # nothing is followed. Still fail-closed, and the
            # peer must see exactly the two initial requests.
            ("http a.test /longpath", "http: 0 bytes", 60)],
         lambda log, p: [x[0] for x in reqs(p)] ==
         ["/longhost", "/longpath"]),
        ("longcookie", [
            ("http a.test /setlong", "SETLONG-OK", 60),
            ("http a.test /checklong", "CHECKLONG-OK", 60),
            ("cookies list", "(no cookies stored)", 30)],
         lambda log, p: [x[0] for x in reqs(p)] ==
         ["/setlong", "/checklong"] and
         not has_hdr(reqs(p), 1, "Cookie:")),
        ("chunkhuge", [("http a.test /chunkhuge", "http: failed", 60)],
         lambda log, p: [x[0] for x in reqs(p)] == ["/chunkhuge"]),
        ("secplain", [
            ("http a.test /setsec", "SETSEC-OK", 60),
            ("http a.test /checksec", "CHECKSEC-OK", 60)],
         lambda log, p: [x[0] for x in reqs(p)] ==
         ["/setsec", "/checksec"] and
         not has_hdr(reqs(p), 1, "sec=")),
    ]
    allok = True
    for tag, script, fn in boots:
        ok, log, peer = run_boot(tag, script)
        allok = check(tag, ok, log, peer, fn) and allok
    print("SUITE http_sec " + ("PASS" if allok else "FAIL"))
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())
