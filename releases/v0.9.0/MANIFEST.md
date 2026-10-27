# nxtsOS v0.9.0 — Release Manifest (Phase 9: networking)

- Version: 0.9.0 (Phase 9, whole phase in one release, per the user's choice)
- Kernel binary: `build/nxtsOS.bin` (~139 KiB)
- Bootable image: `build/nxtsOS.iso` (El Torito via grub-mkrescue)
- Build command: `./scripts/build.sh` (also builds `build/calc.nxpkg`)
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Git tag: `v0.9.0` (local repository only)
- Source archive: `archives/code/nxtsOS-v0.9.0-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.9.0-dist.zip`
  (includes the ISO, `calc.nxpkg`, `bochsrc.txt`, `mkdisk.py`,
  VM_GUIDE, BUILD_AND_TEST, MANIFEST, TEST_REPORT,
  SECURITY_REPORT, README, VERSION)
- Checksums: `releases/v0.9.0/SHA256SUMS`

## What is new in v0.9.0

User request (2026-10-27, after v0.8.0 delivered): "continue" —
interpreted as proceeding with Phase 9 networking, the next
phase in the core-first roadmap. This release is all three
Phase 9 tasks (9.1 stack, 9.2 TLS, 9.3 adversarial test).

### 9.1 — Network stack (net/e1000.c, net/net.c, net/tcp.c, net/nettest.c)

- e1000 driver, polled (no interrupts): PCI scan, BAR0 MMIO
  uncached, RX ring 32 / TX ring 8, 2048-byte buffers.
  Register-offset bug found and fixed in testing (BAL/LEN
  pairs were swapped; `netdbg` readback exposed it).
  QEMU quirk handled: QEMU advances TDH but never sets
  the DD bit, so sends wait for TDH advancement or DD.
- Ethernet / ARP (8-entry cache, 300 s) / IPv4 (strict
  validation, fragments dropped) / ICMP echo / UDP.
  UDP dispatch by destination port: 68 DHCP, 53 or 5353
  DNS (replies arrive at the client's source port 5353).
- DHCP client (discover → offer → request → ACK, strict
  option bounds, sane fallbacks), DNS client (label
  validation, first A record, CNAMEs skipped not
  followed, compression pointers skipped never followed,
  pointer targets bounds-checked), TCP client (one
  connection, MSS 1460, in-order data into a 4096-byte
  buffer, FIN handling), HTTP/1.0 client (body until
  close or Content-Length, chunked refused).
- Shell commands: `netinfo`, `netdbg`, `dhcp`,
  `ping <ip>`, `dns <name>`, `dnsset <ip>`, `http`,
  `https`, `nettest` (10 malformed-frame injection
  cases, all dropped cleanly).

### 9.2 — TLS 1.2 client (net/tls.c, net/bignum.c)

- One suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C),
  RSA key exchange, TLS 1.2 only. Full handshake
  verified against real OpenSSL: SNI +
  signature_algorithms ClientHello extensions, RSA
  premaster (PKCS#1 v1.5), TLS PRF master/key block,
  Finished both ways, AES-128-GCM app data with tag
  verified before decrypting.
- X.509 chain verification: dates vs CMOS RTC, issuer
  == next subject, non-leaf issuers must be CA:true,
  RSA PKCS#1 v1.5 signature verification via a
  from-scratch 2048-bit bignum (schoolbook multiply,
  binary long division), SAN-only hostname matching
  (exact, no wildcards; IP hosts match SAN IPs).
  Certificate failure is a distinct -2 ("certificate
  refused, connection not made"), never a silent
  plaintext fallback.
- Honest limits (also in docs/NETWORKING.md): NO CA
  trust store — chains must end in a self-signed root
  (TOFU, not CA authentication; a MITM with their own
  self-signed cert for the same host would also pass);
  RNG is a timer/MAC-seeded xorshift32, NOT
  cryptographic (the release's weakest link; TCP ISNs
  are likewise predictable); no ECDHE, resumption,
  ALPN, client certs, revocation, or TLS 1.3; GCM tag
  comparison is not constant-time.
- Bugs found by testing against real servers and fixed:
  missing SNI extension length field, cipher suite
  0x009E (DHE_RSA) offered instead of 0x009C (RSA),
  missing signature_algorithms extension (OpenSSL 3
  aborts without it), `sizeof(msg)` == 4 after moving
  the handshake buffer to static storage (rejected
  every ServerHello), `bn_from_be` rejecting 257-byte
  RSA moduli before stripping the leading zero, app
  data records larger than the 1024-byte read buffer
  failing the fetch (spill buffering added), shell
  HTTP body buffer 2048 bytes too small for a 5001-byte
  body (raised to 8192). Large record buffers are
  static, not stack: the kernel stack is 16 KiB.

### 9.3 — Adversarial network test (tests/security_test_net.py)

- 400-frame ARP/garbage flood: guest survives, ping
  and netinfo still work afterwards.
- Malformed DNS pointer (target past the packet end):
  lookup fails cleanly, shell stays alive.
- Wrong-host TLS cert, tampered-signature cert, and
  expired cert: all refused with "certificate refused".
- Plain HTTP on a TLS port: handshake fails
  ("https: failed"), not misreported as a certificate
  refusal. Shell alive after all cases.

## NOT implemented in v0.9.0

User-mode socket API (kernel stack + shell commands
only), graphical network settings, multi-connection
TCP, IPv4 fragmentation reassembly, DNS CNAME
following, DNS over TCP, DHCP renewal/release,
graphical boot login (unchanged), GUI apps beyond
Calculator (unchanged), package signing (unchanged).

## NOT tested

Android Bochs (no Android device in sandbox),
VirtualBox / real hardware, real mouse movement with
a real pointer (scripted injection only), phone FPS,
Calculator arithmetic beyond the '7' key, slirp DNS
in this sandbox (environment UDP block, proven — the
peer-harness suite covers DNS strictly instead).
