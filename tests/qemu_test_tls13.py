#!/usr/bin/env python3
"""web/SSL Phase 2 test: TLS 1.3 client + ECDSA for TLS 1.2.

Boots (guest runs `dhcp` first; peer is tls_peer_lib.SslPeer
unless noted):
  tls13-rsa:        TLS 1.3, RSA chain, TOFU -> body fetched,
                    peer negotiated TLSv1.3 / TLS_AES_128_GCM_SHA256.
  tls13-ec:         TLS 1.3, ECDSA chain, TOFU -> body fetched,
                    peer negotiated TLSv1.3.
  tls13-store-rsa:  TLS 1.3, RSA chain, store mode (castore.txt
                    holds the RSA CA modulus) -> fetched.
  tls13-store-ec:   TLS 1.3, ECDSA chain, store mode (castore.txt
                    holds the EC CA point) -> fetched.
  tls13-anchored:   TLS 1.3, RSA chain, anchored mode
                    (tlsanchors.txt holds the RSA CA modulus).
  tls12-rsa:        TLS 1.2, RSA chain, TOFU -> fetched
                    (combined-hello fallback still works).
  tls12-ec:         TLS 1.2, ECDSA chain, TOFU -> fetched
                    (ECDSA for TLS 1.2).
  tls13-expired:    TLS 1.3, expired leaf -> certificate refused.
  tls13-wronghost:  TLS 1.3, SAN mismatch -> certificate refused.
  tls13-badsig:     TLS 1.3, leaf signed by another CA ->
                    certificate refused.
  tls13-tofu-mismatch: disk-backed TOFU: first fetch accepts
                    and pins, second fetch with a different leaf
                    for the same host -> certificate refused.
  downgrade-legacy: raw ServerHello with legacy_version 0x0301
                    -> "https: failed", no body, no panic.
  downgrade-sentinel-00 / downgrade-sentinel-01: raw ServerHello
                    TLS 1.2 carrying the DOWNGRD sentinel with
                    last byte 0x00 / 0x01 (both values the kernel
                    enforces) -> "https: failed".

Usage: python3 tests/qemu_test_tls13.py <iso> <workdir>
<workdir> is created by tests/qemu_test_tls13_setup.py.
Port 12353 is used so this suite can run alongside the
castore suite (port 12352).
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
PORT = 12353


class RawPeer13(lib.NetPeer):
    """Minimal raw peer: answers the first ClientHello with a
    single crafted ServerHello, then stays silent. mode 'legacy'
    sends legacy_version 0x0301; modes 'sentinel00'/'sentinel01'
    send a TLS 1.2 ServerHello whose random carries the DOWNGRD
    sentinel with last byte 0x00 / 0x01 — both values the kernel
    enforces, so both are tested."""

    def __init__(self, mode, listen_port, debug_path=None):
        self.mode = mode
        self.sent = False
        super().__init__(listen_port, debug_path)

    def tls_reset(self):
        self.sent = False

    def tls_feed(self, src_mac, data):
        if self.sent:
            return
        self.sent = True
        if self.mode == "legacy":
            body = bytes([0x03, 0x01]) + bytes(32) + bytes([0, 0x00, 0x9C, 0, 0, 0])
        else:
            last = 0x00 if self.mode == "sentinel00" else 0x01
            rnd = bytes(24) + b"DOWNGRD" + bytes([last])
            body = bytes([0x03, 0x03]) + rnd + bytes([0, 0xC0, 0x2F, 0, 0, 0])
        msg = bytes([2]) + len(body).to_bytes(3, "big") + body
        rec = bytes([22, 0x03, 0x03]) + len(msg).to_bytes(2, "big") + msg
        self.send_queue += rec
        self.maybe_send(src_mac)


def run_boot(tag, make_peer, disk_src, script):
    serial = os.path.join(WORK, f"tls13-{tag}-serial.log")
    mon = os.path.join(WORK, f"tls13-{tag}-mon.sock")
    disk = None
    if disk_src:
        disk = os.path.join(WORK, f"tls13-{tag}.img")
        shutil.copy(disk_src, disk)
    for p in (serial, mon):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
    qemu = lib.start_qemu(ISO, serial, mon, disk, listen_port=PORT)
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

            before = len(lib.log_text(serial))
            type_cmd(txt)
            for _ in range(150):
                fresh = lib.log_text(serial)[before:]
                if f"root@nxts> {txt}" in fresh:
                    return
                if fresh.count("root@nxts> ") >= 1:
                    break
                time.sleep(0.1)
            if f"root@nxts> {txt}" not in lib.log_text(serial)[before:]:
                before2 = len(lib.log_text(serial))
                type_cmd(txt)
                for _ in range(150):
                    if f"root@nxts> {txt}" in lib.log_text(serial)[before2:]:
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
    for e in getattr(peer, "ssl_errors", []):
        print(f"  {tag}: peer ssl error: {e}")
        ok = False
    return ok, log, peer


def ssl_peer(chains, marker, min_v=None, max_v=None, ciphers=None):
    return lib.SslPeer(chains, {"/": marker}, PORT,
                       min_version=min_v, max_version=max_v, ciphers=ciphers)


def check(tag, ok, log, peer, want_version=None, want_body=None,
          want_absent=()):
    if want_version is not None:
        got = getattr(peer, "negotiated", [])
        if not got or got[0][0] != want_version:
            print(f"  {tag}: negotiated {got}, want {want_version}")
            ok = False
        else:
            print(f"  {tag}: negotiated {got[0][0]} {got[0][1]}")
    if want_body is not None and want_body not in log:
        print(f"  {tag}: body marker missing: {want_body}")
        ok = False
    for a in want_absent:
        if a in log:
            print(f"  {tag}: unexpected present: {a}")
            ok = False
    print(f"  {tag}: {'PASS' if ok else 'FAIL'}")
    return ok


def main():
    need = ["chain-rsa13.pem", "rsa-leaf-key.pem", "chain-ec13.pem",
            "ec-leaf-key.pem", "chain-wrong.pem", "wrong-leaf-key.pem",
            "chain-badsig13.pem", "badsig-leaf-key.pem",
            "chain-rsa13-b.pem", "leaf2-key.pem", "chain-expired.pem",
            "expired-leaf-key.pem", "disk-store-rsa.img", "disk-store-ec.img",
            "disk-anchor.img", "disk-tofu.img"]
    for name in need:
        if not os.path.isfile(os.path.join(WORK, name)):
            print(f"missing fixture {name} — run "
                  "tests/qemu_test_tls13_setup.py first")
            return 1
    results = []
    V13 = ssl.TLSVersion.TLSv1_3
    V12 = ssl.TLSVersion.TLSv1_2

    def W(p):
        return os.path.join(WORK, p)

    # 1. TLS 1.3, RSA chain, TOFU.
    ok, log, p = run_boot("tls13-rsa", lambda: ssl_peer([(W("chain-rsa13.pem"), W("rsa-leaf-key.pem"))],
                 b"NXTS-TLS13-RSA-OK", min_v=V13, max_v=V13), None,
                          [("https tls13.test /", "NXTS-TLS13-RSA-OK", 90)])
    results.append(check("tls13-rsa", ok, log, p, want_version="TLSv1.3",
                         want_body="NXTS-TLS13-RSA-OK",
                         want_absent=("certificate refused", "https: failed")))

    # 2. TLS 1.3, ECDSA chain, TOFU.
    ok, log, p = run_boot("tls13-ec", lambda: ssl_peer([(W("chain-ec13.pem"), W("ec-leaf-key.pem"))],
                 b"NXTS-TLS13-EC-OK", min_v=V13, max_v=V13), None,
                          [("https tls13ec.test /", "NXTS-TLS13-EC-OK", 90)])
    results.append(check("tls13-ec", ok, log, p, want_version="TLSv1.3",
                         want_body="NXTS-TLS13-EC-OK",
                         want_absent=("certificate refused", "https: failed")))

    # 3. TLS 1.3, RSA chain, store mode.
    ok, log, p = run_boot("tls13-store-rsa", lambda: ssl_peer([(W("chain-rsa13.pem"), W("rsa-leaf-key.pem"))],
                 b"NXTS-TLS13-RSA-OK", min_v=V13, max_v=V13), W("disk-store-rsa.img"),
                          [("httpss tls13.test /", "NXTS-TLS13-RSA-OK", 90)])
    results.append(check("tls13-store-rsa", ok, log, p, want_version="TLSv1.3",
                         want_body="NXTS-TLS13-RSA-OK",
                         want_absent=("certificate refused", "httpss: failed")))

    # 4. TLS 1.3, ECDSA chain, store mode.
    ok, log, p = run_boot("tls13-store-ec", lambda: ssl_peer([(W("chain-ec13.pem"), W("ec-leaf-key.pem"))],
                 b"NXTS-TLS13-EC-OK", min_v=V13, max_v=V13), W("disk-store-ec.img"),
                          [("httpss tls13ec.test /", "NXTS-TLS13-EC-OK", 90)])
    results.append(check("tls13-store-ec", ok, log, p, want_version="TLSv1.3",
                         want_body="NXTS-TLS13-EC-OK",
                         want_absent=("certificate refused", "httpss: failed")))

    # 5. TLS 1.3, RSA chain, anchored mode.
    ok, log, p = run_boot("tls13-anchored", lambda: ssl_peer([(W("chain-rsa13.pem"), W("rsa-leaf-key.pem"))],
                 b"NXTS-TLS13-RSA-OK", min_v=V13, max_v=V13), W("disk-anchor.img"),
                          [("httpsa tls13.test /", "NXTS-TLS13-RSA-OK", 90)])
    results.append(check("tls13-anchored", ok, log, p, want_version="TLSv1.3",
                         want_body="NXTS-TLS13-RSA-OK",
                         want_absent=("certificate refused", "httpsa: failed")))

    # 6. TLS 1.2 fallback, RSA chain, TOFU.
    ok, log, p = run_boot("tls12-rsa", lambda: ssl_peer([(W("chain-rsa13.pem"), W("rsa-leaf-key.pem"))],
                 b"NXTS-TLS13-RSA-OK", min_v=V12, max_v=V12), None,
                          [("https tls13.test /", "NXTS-TLS13-RSA-OK", 90)])
    results.append(check("tls12-rsa", ok, log, p, want_version="TLSv1.2",
                         want_body="NXTS-TLS13-RSA-OK",
                         want_absent=("certificate refused", "https: failed")))

    # 7. TLS 1.2, ECDSA chain, TOFU.
    ok, log, p = run_boot("tls12-ec", lambda: ssl_peer([(W("chain-ec13.pem"), W("ec-leaf-key.pem"))],
                 b"NXTS-TLS13-EC-OK", min_v=V12, max_v=V12,
                 ciphers="ECDHE-ECDSA-AES128-GCM-SHA256"), None,
                          [("https tls13ec.test /", "NXTS-TLS13-EC-OK", 90)])
    results.append(check("tls12-ec", ok, log, p, want_version="TLSv1.2",
                         want_body="NXTS-TLS13-EC-OK",
                         want_absent=("certificate refused", "https: failed")))

    # 8-10. Negatives (TLS 1.3).
    for tag, chain, key in (
            ("tls13-expired", "chain-expired.pem", "expired-leaf-key.pem"),
            ("tls13-wronghost", "chain-wrong.pem", "wrong-leaf-key.pem"),
            ("tls13-badsig", "chain-badsig13.pem", "badsig-leaf-key.pem")):
        ok, log, p = run_boot(tag, lambda: ssl_peer([(W(chain), W(key))], b"NXTS-TLS13-XXX",
                     min_v=V13, max_v=V13), None,
                              [("https tls13.test /",
                                "https: certificate refused", 90)])
        results.append(check(tag, ok, log, p,
                             want_absent=("NXTS-TLS13-XXX",)))

    # 11. TOFU fingerprint mismatch (disk-backed).
    ok, log, p = run_boot("tls13-tofu-mismatch", lambda: ssl_peer([(W("chain-rsa13.pem"), W("rsa-leaf-key.pem")),
                  (W("chain-rsa13-b.pem"), W("leaf2-key.pem"))],
                 b"NXTS-TLS13-RSA-OK", min_v=V13, max_v=V13), W("disk-tofu.img"),
                          [("https tls13.test /", "NXTS-TLS13-RSA-OK", 90),
                           ("https tls13.test /",
                            "https: certificate refused", 90)])
    results.append(check("tls13-tofu-mismatch", ok, log, p,
                         want_version="TLSv1.3",
                         want_body="NXTS-TLS13-RSA-OK"))

    # 12-14. Downgrade attacks (raw peers).
    for tag, mode in (("downgrade-legacy", "legacy"),
                      ("downgrade-sentinel-00", "sentinel00"),
                      ("downgrade-sentinel-01", "sentinel01")):
        ok, log, p = run_boot(tag, lambda: RawPeer13(mode, PORT, f"{WORK}/tls13-{tag}.dbg"), None,
                              [("https tls13.test /", "https: failed", 90)])
        results.append(check(tag, ok, log, p,
                             want_absent=("NXTS-TLS13-RSA-OK",
                                          "certificate refused")))
    print(f"TLS13: {sum(results)}/{len(results)} PASS")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
