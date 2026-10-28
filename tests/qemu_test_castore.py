#!/usr/bin/env python3
"""web/SSL Phase 1 test: CA store (castore.txt) + store-mode
verification + TOFU leaf pins + signed-bundle update + CSPRNG.

Peer: tests/tls_peer_lib.py SslPeer (full TLS 1.2 handshake,
RSA-AES128-GCM). Guest DNS answers every name, so a refusal
cannot be a DNS failure.

Cases (one boot each; guest runs `dhcp` first):
  store-good:     disk carries castore.txt with the store
                  intermediate's modulus; peer chain is
                  [leaf, store-int, root4096] -> `httpss
                  store.test /` SUCCEEDS (4096 tail harmless
                  in store mode) AND `httpss other.test /`
                  in the same boot is refused (host match).
                  Then `castore add newroot.txt` (a second
                  root from a file) succeeds and `castore
                  list` shows 2 roots.
  store-nostore:  no castore.txt -> refused.
  store-wrong:    castore.txt holds an unrelated modulus ->
                  refused.
  store-badsig:   leaf signed by a different key under the
                  same intermediate subject -> refused.
  store-oversize: store holds store-root (2048); chain is
                  [leaf, int4096, store-root]. The leaf's
                  link into the 4096-bit intermediate cannot
                  verify, so the chain refuses EVEN THOUGH
                  trust exists further up.
  store-big:      disk carries a 20-root store (19 dummy
                  lines + the real store-int modulus LAST,
                  10260 bytes — past the old 8192-byte
                  whole-file read): `httpss store.test /`
                  must still SUCCEED, proving the windowed
                  membership scan reaches the last root.
  tofu-print:     peer serves self-signed tofuA, then
                  self-signed tofuB for the same host:
                  first `https tofu.test /` succeeds, `cat
                  tofuprints.txt` shows the pinned SHA-256,
                  second fetch refuses with a fingerprint
                  mismatch message.
  csprng:         no peer; `csprngtest` prints the RFC 8439
                  vector OK line and PASS.
  update-good:    disk carries tlsanchors.txt (store-int);
                  peer serves /castore.txt + /castore.txt.sig
                  (vendor-signed via tools/mksig.py):
                  `castore update update.test` installs 1
                  root, `castore list` shows it, then
                  `httpss store.test /` succeeds.
  update-badsig:  same, but the bundle is tampered (original
                  signature) -> "signature invalid, not
                  installed" and `castore list` shows no store.

Usage: qemu_test_castore.py <iso> <workdir>
<workdir> is created by tests/qemu_test_castore_setup.py.
Exit 0 only if every case passes. Always terminates QEMU.
"""
import importlib.util
import os
import shutil
import subprocess
import sys
import threading
import time

ISO, WORK = sys.argv[1:3]
os.makedirs(WORK, exist_ok=True)
LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "tls_peer_lib.py")
spec = importlib.util.spec_from_file_location("tls_peer_lib", LIB)
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)

PORT = 12352
PROMPT = "root@nxts> "


def boot(tag, disk_src, chain_files, steps, routes, use_peer=True):
    """steps: [(command, [markers], timeout)]. markers must all
    appear (in any order within the step's window)."""
    serial = os.path.join(WORK, f"castore-{tag}-serial.log")
    mon = os.path.join(WORK, f"castore-{tag}-mon.sock")
    disk = None
    if disk_src:
        disk = os.path.join(WORK, f"castore-{tag}.img")
        shutil.copy(disk_src, disk)
    for p in (serial, mon):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
    qemu = lib.start_qemu(ISO, serial, mon, disk, PORT)
    peer = None
    if use_peer:
        peer = lib.SslPeer(chain_files, routes, PORT,
                           f"{WORK}/castore-{tag}.dbg")
        threading.Thread(target=peer.run, daemon=True).start()
    ok = True
    try:
        if not lib.wait_mon(mon):
            print(f"  {tag}: monitor never appeared")
            return False
        if not lib.wait_prompt(serial, PROMPT, 60):
            print(f"  {tag}: prompt never appeared")
            return False
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
                if f"{PROMPT}{txt}" in fresh:
                    return
                if fresh.count(PROMPT) >= 1:
                    break
                time.sleep(0.1)
            if f"{PROMPT}{txt}" not in lib.log_text(serial)[before:]:
                before2 = len(lib.log_text(serial))
                type_cmd(txt)
                for _ in range(150):
                    if f"{PROMPT}{txt}" in lib.log_text(serial)[before2:]:
                        break
                    time.sleep(0.1)

        send_text("dhcp")
        time.sleep(8)
        for cmd, markers, timeout in steps:
            send_text(cmd)
            for m in markers:
                ok &= lib.wait_for(
                    serial, lambda t, m=m: m in t, timeout,
                    f"{tag} {cmd} -> {m}")
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
    for m in ("PANIC", "EXCEPTION", "page fault"):
        if m in log:
            print(f"  {tag}: FORBIDDEN marker present: {m}")
            ok = False
    if peer is not None and peer.ssl_errors:
        print(f"  {tag}: peer ssl errors: {peer.ssl_errors}")
        ok = False
    print(f"  {tag}: {'PASS' if ok else 'FAIL'}")
    return ok


def main():
    need = ["chain-store.pem", "leaf-key.pem", "chain-badsig.pem",
            "badsig-leaf-key.pem", "chain-oversize.pem",
            "ov-leaf-key.pem", "tofuA-cert.pem", "tofuA-key.pem",
            "tofuB-cert.pem", "tofuB-key.pem", "disk-store.img",
            "disk-nostore.img", "disk-wrong.img", "disk-oversize.img",
            "disk-anchor.img", "disk-big.img", "disk-tofu.img", "castore-bundle.txt",
            "castore-bundle.txt.sig", "tampered-bundle.txt",
            "tofuA.sha256"]
    for name in need:
        if not os.path.isfile(os.path.join(WORK, name)):
            print(f"missing fixture {name} — run "
                  "tests/qemu_test_castore_setup.py first")
            return 1
    fp = open(os.path.join(WORK, "tofuA.sha256")).read().strip()
    bundle = open(os.path.join(WORK, "castore-bundle.txt"), "rb").read()
    sig = open(os.path.join(WORK, "castore-bundle.txt.sig"), "rb").read()
    tampered = open(os.path.join(WORK, "tampered-bundle.txt"), "rb").read()
    store_chain = [(f"{WORK}/chain-store.pem", f"{WORK}/leaf-key.pem")]
    routes_ok = {"/": b"NXTS-CASTORE-OK\n"}
    all_ok = True

    all_ok &= boot("store-good", f"{WORK}/disk-store.img", store_chain,
                   [("httpss store.test /", ["NXTS-CASTORE-OK"], 90),
                    ("httpss other.test /", ["certificate refused"], 90),
                    ("castore add newroot.txt", ["castore: added"], 30),
                    ("castore list", ["castore: 2 roots"], 30)],
                   routes_ok)
    time.sleep(1)
    all_ok &= boot("store-nostore", f"{WORK}/disk-nostore.img",
                   store_chain,
                   [("httpss store.test /", ["certificate refused"], 90)],
                   routes_ok)
    time.sleep(1)
    all_ok &= boot("store-wrong", f"{WORK}/disk-wrong.img", store_chain,
                   [("httpss store.test /", ["certificate refused"], 90)],
                   routes_ok)
    time.sleep(1)
    all_ok &= boot("store-badsig", f"{WORK}/disk-store.img",
                   [(f"{WORK}/chain-badsig.pem",
                     f"{WORK}/badsig-leaf-key.pem")],
                   [("httpss store.test /", ["certificate refused"], 90)],
                   routes_ok)
    time.sleep(1)
    all_ok &= boot("store-oversize", f"{WORK}/disk-oversize.img",
                   [(f"{WORK}/chain-oversize.pem",
                     f"{WORK}/ov-leaf-key.pem")],
                   [("httpss store.test /", ["certificate refused"], 90)],
                   routes_ok)
    time.sleep(1)
    all_ok &= boot("store-big", f"{WORK}/disk-big.img", store_chain,
                   [("httpss store.test /", ["NXTS-CASTORE-OK"], 90)],
                   routes_ok)
    time.sleep(1)
    all_ok &= boot("tofu-print", f"{WORK}/disk-tofu.img",
                   [(f"{WORK}/tofuA-cert.pem", f"{WORK}/tofuA-key.pem"),
                    (f"{WORK}/tofuB-cert.pem", f"{WORK}/tofuB-key.pem")],
                   [("https tofu.test /", ["NXTS-TOFU-OK"], 90),
                    ("cat tofuprints.txt", [fp], 30),
                    ("https tofu.test /",
                     ["fingerprint mismatch", "certificate refused"], 90)],
                   {"/": b"NXTS-TOFU-OK\n"})
    time.sleep(1)
    all_ok &= boot("csprng", None, [], [
        ("csprngtest", ["csprng: vector OK", "csprngtest PASS"], 60),
    ], {}, use_peer=False)
    time.sleep(1)
    all_ok &= boot("update-good", f"{WORK}/disk-anchor.img", store_chain,
                   [("castore update update.test",
                     ["castore: updated 1 roots"], 120),
                    ("castore list", ["castore: 1 roots"], 30),
                    ("httpss store.test /", ["NXTS-CASTORE-OK"], 90)],
                   {"/castore.txt": bundle, "/castore.txt.sig": sig,
                    "/": b"NXTS-CASTORE-OK\n"})
    time.sleep(1)
    all_ok &= boot("update-badsig", f"{WORK}/disk-anchor.img", store_chain,
                   [("castore update update.test",
                     ["signature invalid, not installed"], 120),
                    ("castore list", ["castore: no store"], 30)],
                   {"/castore.txt": tampered, "/castore.txt.sig": sig,
                    "/": b"NXTS-CASTORE-OK\n"})
    print("RESULT:", "PASS" if all_ok else "FAIL")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
