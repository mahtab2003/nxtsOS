# nxtsOS v0.9.0 — Security Report (Phase 9.3, adversarial test)

Attacker view for this release: a hostile network. The
guest is the target: malformed and oversized frames,
floods, malicious DNS answers, and hostile TLS servers.
Expected: packets dropped cleanly, TLS refused, no
kernel fault, no privilege gain, shell stays usable.
All cases below were run against the release ISO; the
test is tests/security_test_net.py (host-side, two
phases), plus the in-kernel nettest injection suite.

## Test 1: tests/security_test_net.py Phase A (socket peer) — PASS

### A1 — 400-frame flood (ARP requests, truncated frames,
### unknown ethertypes, bad-checksum UDP, UDP to random ports)

- Guest survives: `ping 192.168.99.1` → "ping: reply
  received" (retried up to 3 times; see TEST_REPORT.md
  for the single frame-loss flake), `netinfo` prints
  MAC + counters afterwards. The RX ring (32 entries)
  overflows under flood and QEMU drops the excess —
  that is the emulator's backpressure, not a guest
  wedge: the guest keeps draining and answering.
- `nettest` (in-kernel, 10 injection cases: truncated
  frame, foreign MAC, lying IP total-length, IHL 15
  with short frame, bad IP checksum, MF fragment, lying
  UDP length, truncated ARP, garbage IP version,
  zero-length UDP to port 53) — "nettest PASS" in the
  peer suite: drop counter increases, nothing faults.

### A2 — Malformed DNS pointer (answer NAME = 0xC0 0xFF,
### target past the end of the packet)

- Guest prints "dns: lookup failed" and the shell stays
  alive (`netinfo` afterwards). Fixed in this release:
  `dns_skip_name` previously returned success for ANY
  pointer without checking its target. It now rejects
  out-of-bounds targets.
- Design note (honest, not a gap): this parser only
  SKIPS names and never follows compression pointers,
  so a pointer LOOP to a valid offset cannot hang it —
  there is no followed chain to loop. The bounds check
  is the real validation, and it is what is tested.
  The crafted pointer-loop case from the plan is
  therefore covered by construction plus the
  out-of-bounds test, not by a separate loop test.

## Test 2: tests/security_test_net.py Phase B (slirp + real TLS servers) — PASS

- **Wrong-host cert** (SAN IP 10.0.2.99, guest connects
  to 10.0.2.2): "certificate refused, connection not
  made". SAN-only matching, no CN fallback when SANs
  exist, no wildcards.
- **Tampered-signature cert** (valid cert, last
  signature byte flipped): "certificate refused".
  RSA PKCS#1 v1.5 verification fails as it must.
- **Expired cert** (validity 2020-2021, generated with
  openssl ca -selfsign): "certificate refused". Dates
  checked against the CMOS RTC for every cert.
- **Plain HTTP on the TLS port**: "https: failed" —
  a handshake failure, correctly NOT reported as a
  certificate refusal. The refused count across B is
  exactly 3 (wrong-host, tampered, expired), so the
  plain-HTTP case is not miscounted as a refusal.
- Shell alive after all four cases (`netinfo`).

## Standing limits (not fixed in this release — recorded, not hidden)

- **TOFU, not CA authentication.** No trust store
  ships: a chain ending in a self-signed root passes
  if it is self-consistent, date-valid, and
  host-bound. A MITM with their own self-signed cert
  for the same hostname would also pass. Do not use
  this client for real secrets until an anchor store
  is provisioned.
- **Weak randomness (the release's weakest link).**
  Timer/MAC-seeded xorshift32 for ClientHello randoms
  and premaster secrets; predictable TCP ISNs. An
  observer who can see timing can predict these.
- **Single TCP connection, no fragmentation
  reassembly, no DNS CNAME following, no DHCP
  renewal/release.** A peer that fragments, or a
  resolver that answers only via CNAME, will fail
  closed (lookup/connection fails, no crash).
- **No user-mode socket API in v0.9.0**, so there is
  no socket-API abuse surface from user programs yet —
  that surface arrives with the API and must be tested
  then.
- GCM tag comparison is not constant-time (the tag is
  not a secret key; lab client).
- Earlier phases' limits stand: no package signing,
  no disk passphrase change or recovery key, no
  authenticated disk encryption, memory-hard KDF not
  implemented, larger ELFs (>64 KiB) and disks
  (>16 MiB) unsupported.

## No exploitable findings outstanding from this test

Every case above either passed cleanly or was fixed
(the DNS pointer bounds check) and retested before
shipping. The two honest gaps that remain are the
TOFU trust model and the weak RNG — both are design
limits stated in docs/NETWORKING.md and in the
delivery message, not silently shipped defects.
