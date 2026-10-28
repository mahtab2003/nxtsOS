# nxtsOS Networking (Phase 9, v0.9.0)

How the guest talks to a network, what it verifies, and what
it deliberately does not do. Read this before claiming
anything about nxtsOS networking: the honest limits are
part of the design, not footnotes.

## Stack (all in `net/`)

- **Driver: e1000, polled, no interrupts** (`net/e1000.c`).
  PCI scan (bus 0, vendor 0x8086, class 0x02) for device IDs
  0x100E/0x100F/0x1010/0x1017/0x1008/0x1011; BAR0 MMIO
  mapped uncached at 0x41000000; RX ring 32 descriptors,
  TX ring 8, 2048-byte buffers. RCTL = EN|BAM|SECRC,
  TCTL = EN|PSP, TIPG 10/10/10, IMS = 0. Polling follows the
  keyboard decision: an interrupt the emulator never
  delivers is a single point of failure; a polled ring is
  not. A missing NIC never fails the boot (`net_init`
  runs after `sti` because its reset wait needs PIT ticks).
  Register map note: the e1000 datasheet offsets are
  RDBAL 0x2800 / RDLEN 0x2808 and TDBAL 0x3800 /
  TDLEN 0x3808 — an earlier draft had the BAL/LEN pairs
  swapped, which sent the ring address into the length
  register and transmitted nothing. `netdbg` (register
  readback) is what exposed it; keep that command.
- **TX completion quirk:** QEMU advances TDH when it
  processes a descriptor but never writes back the DD
  status bit, so `net_send` waits for TDH advancement
  OR DD, 100-tick timeout, then counts a drop. Sends are
  serialised (each send waits for completion).
- **Ethernet/ARP/IPv4/ICMP/UDP** (`net/net.c`): ARP cache
  8 entries, 300 s expiry (evict slot 0 when full);
  routing by netmask, else via gateway; broadcast needs
  no ARP; payload caps (IP 1400, UDP 1300). IPv4 receive
  validation: frame length, destination MAC, version 4,
  IHL bounds, total-length bounds, header checksum must
  fold to zero, **fragmented packets are dropped** (MF or
  offset set — no reassembly in v0.9.0), destination must
  be our IP or broadcast once configured — before DHCP
  completes, `configured` is still 0 and the destination
  check is skipped entirely (`net_rx_frame` enforces it
  only inside `if (configured)`), so stray packets
  addressed elsewhere are also accepted in the pre-DHCP
  window, not just 0.0.0.0/broadcast as the code comment
  suggests. CORRECTION: the previous wording stated the
  destination rule without the pre-DHCP exception.
  UDP dispatch by destination
  port: 68 DHCP, 53 or 5353 DNS (DNS replies arrive at
  the client's source port 5353, not 53 — dispatching
  only on 53 dropped every reply during testing).
- **DHCP client:** discover (broadcast flag, parameter
  list 1,3,6,51) → offer → request (options 50+54) →
  ACK; xid derived from ticks; 2 rounds, 300-tick waits;
  options parsed with strict bounds; fallbacks mask
  /24, gateway = server, DNS = gateway.
- **DNS client:** query id from ticks, source port 5353;
  label validation (<=63, character set, bounds); answer
  walk returns the first A record; CNAMEs are skipped,
  **not followed**; compression pointers are never
  followed (names are only skipped) and pointer targets
  are bounds-checked — an out-of-bounds pointer is a
  malformed response and the lookup fails.
- **TCP client** (`net/tcp.c`): one connection only.
  States CLOSED/SYN_SENT/ESTABLISHED/FIN_SENT; local
  port 49152 + ticks%10000; SYN carries MSS 1460;
  checksums verified by zero-and-compare; ACK progress
  only forward; in-order data only into a 4096-byte
  buffer (out-of-order or gap → re-ACK current rcv_nxt;
  buffer-full → take what fits, the peer retransmits
  the rest); FIN handling sets peer_closed; close sends
  FIN|ACK and polls 50 ticks. Advertised window is a
  constant 4096 (the buffer size), not room-based.
- **HTTP client:** HTTP/1.0, body until close or
  Content-Length; chunked Transfer-Encoding is refused
  only when the header name arrives in exactly that
  case (`net_http_get` matches the literal bytes
  "Transfer-Encoding:") — a server sending the
  lowercase name `transfer-encoding: chunked` is NOT
  refused: the raw chunked bytes are returned as the
  body instead (proven live 2026-10-28: a lowercase
  chunked response returned "http: 15 bytes" with the
  chunk framing intact, while the exact-case header
  returned "http: failed"). CORRECTION: the previous
  wording stated chunked encoding is refused without
  the case qualification.
  body cap is the caller's buffer (the shell passes
  8192 bytes — a 5001-byte body fetches fine).
  v0.10.0 change: a body longer than the buffer is
  truncated, not failed — the stored prefix is kept,
  the rest is drained, and `net_fetch_truncated()`
  reports it (shell prints "(truncated)", the Web
  window prints `web: truncated at 8192`). The same
  rule applies to the HTTPS client.

## TLS 1.2 client (`net/tls.c`, `net/bignum.c`)

Two cipher suites, TLS 1.2 only: TLS_ECDHE_RSA_WITH_
AES_128_GCM_SHA256 (0xC02F, offered first) and
TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C). The
handshake was verified against real OpenSSL (s_server
and a python `ssl` server): ClientHello (SNI,
signature_algorithms — OpenSSL 3 servers reject
hellos without the latter — supported_groups
(secp256r1 only), ec_point_formats (uncompressed
only), and ALPN offering http/1.1 — the server's
selected ALPN is not parsed, the client speaks
HTTP/1.1 regardless), ServerHello, Certificate,
ServerKeyExchange (ECDHE only: curve must be
secp256r1, the point must be valid, and the
RSA-SHA256 signature over client_random ||
server_random || params must verify with the leaf
key, or the handshake fails closed with no fallback
to RSA key exchange), ServerHelloDone,
ClientKeyExchange, master secret and key block via
the TLS PRF (P_hash with SHA-256), ChangeCipherSpec,
Finished both ways, then AES-128-GCM app data
(nonce = write_IV || sequence, AAD = sequence ||
type || version || length, tag verified before
decrypting). ClientKeyExchange is RSA-encrypted
premaster for 0x009C (PKCS#1 v1.5 type-2 padding,
non-zero random bytes, 48-byte versioned premaster)
or the ECDH public point for 0xC02F (the premaster
is the 32-byte ECDH shared x coordinate, with no
version prefix; the private scalar is drawn from the
same weak RNG described below).

CORRECTION (2026-10-28, TLS audit): this section
previously said "One cipher suite only:
TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C), RSA key
exchange" and listed "No ECDHE" below. That was the
v1.0.0 client (which offered and required 0x009C
only); Phase 12 added the ECDHE path
(`net/ec256.c`, secp256r1) and the ClientHello
offers 0xC02F first. The old wording survives only
in this note.

**X.509 verification** (the part that must not be
oversold): every certificate's dates are checked
against the CMOS RTC; issuer bytes must equal the next
certificate's subject bytes; every non-leaf issuer must
have BasicConstraints CA:true; signatures are RSA
PKCS#1 v1.5 with the exact SHA-256 DigestInfo prefix,
verified by 2048-bit modular exponentiation
(`net/bignum.c`: 64-limb fixed bignums, schoolbook
multiply, binary long division — no 64-bit division,
which the freestanding kernel cannot link); hostname
matching is SAN-only when SANs exist (DNS names match
exactly, case-insensitive, or by a single-label leading
wildcard: `*.domain` matches exactly one label, so
`one.domain` matches but the bare `domain`, a multi-label
`a.b.domain`, a trailing-dot host, and a mid-label star
like `foo.*.domain` do not; IP hosts match SAN IPs and
never match a DNS SAN, and wildcards never apply to IP
literals), CN fallback only when no SAN exists (the CN
follows the same exact-or-single-label-wildcard rule).
Certificate failure returns -2 and the shell prints
"certificate refused, connection not made"; every
other failure returns -1 ("https: failed").

**What TLS here is NOT (read before deploying
anything against it):**

- **Plain `https` is trust on first use (TOFU), NOT CA
  authentication.** Every link of the presented chain
  must verify (each certificate signed by the next
  one's key), dates must be valid, the leaf must match
  the requested host, and the terminal certificate must
  be either self-signed with a verifying self-signature
  (the single-cert case) or CA-flagged (the real-world
  case: leaf + intermediate, root never sent — fixed
  after the v1.1.0 real-device report, where the old
  self-signed-terminal-only rule refused every real
  site). That proves self-consistency, host binding,
  and private-key possession — and nothing more. A man
  in the middle with their own validly-signed chain
  for the same hostname would also pass.
- **Anchored `httpsa` (Phase 12) pins a trust anchor
  instead.** The terminal certificate must be
  CA-flagged and its RSA-2048 key must equal a pinned
  anchor: the compiled-in anchor (Google Trust
  Services WR1, generated by `tools/genanchor.py`
  into `net/tls_anchor.h`) or a modulus listed in the
  root-owned system file `tlsanchors.txt` (one
  512-hex-char modulus per line, exponent 65537;
  malformed lines are skipped, a missing file is not
  an error). The anchor IS the trust root by pinning:
  an intermediate like WR1 is issued by a root above
  it whose 4096-bit key this 2048-bit kernel cannot
  verify, so the chain is not walked past the anchor.
  A chain terminating anywhere else fails with -2.
- **Randomness is a timer/MAC-seeded xorshift32, NOT
  a cryptographic RNG.** This is the release's weakest
  link: premaster secrets, ClientHello randoms and the
  TCP ISN (ticks * 0x9E3779B9 ^ 0x12345678) are
  predictable to anyone who can observe timing. Fine
  for lab tests, NOT for real secrets.
- No session resumption, no client certificates, no
  revocation checking, no TLS 1.3. ALPN is offered
  (http/1.1) but the server's selection is not
  parsed. GCM tag comparison is not constant-time
  (the tag is not a secret key, and this is a lab
  client).

CORRECTION (2026-10-28, TLS audit): the bullets
above previously said "No CA trust store ships ...
A provisioned anchor store is future work" and
"No ECDHE ... no ALPN". Both were the v1.0.0
position; Phase 12 shipped the pinned-anchor
`httpsa` path and the ECDHE path, and the
ClientHello offers ALPN. The old wording survives
only in this note.

## Shell commands

`netinfo` (MAC, rx/tx/drops, config), `netdbg`
(register + descriptor dump — the diagnostic that
found the register-offset bug), `dhcp`, `ping <ip>`
(dotted quad only), `dns <name>`, `dnsset <ip>`
(override the DNS server, e.g. for testing),
`http <host> <path> [port]`,
`https <host> <path> [port]`, `httpsa <host> <path>
[port]` (anchored handshake — the chain must
terminate in a pinned anchor, see the TLS section
above; prints "httpsa: certificate refused,
connection not made" on certificate failure),
`nettest` (10
malformed-frame injection cases through
`net_rx_frame`; prints `nettest PASS` when the run
completes with failures == 0 and the aggregate drop
counter moved (`net_test_run` checks only
drops-after > drops-before, e.g. "drops 0 -> 10" in
the live slirp run — that is an aggregate check, not
a per-case drop assertion: a single case processed
instead of dropped would not by itself fail the run
while the counter still moved). CORRECTION: the
previous wording stated `nettest PASS` prints only
if every case is dropped cleanly and nothing faults,
which overstated the check the code actually makes.
`hostmatch` (hostname-matching self-test: calls the
real `verify_host` on fabricated leaf structs — SAN
wildcard cases, CN-fallback cases, and IP-branch
cases — and prints "hostmatch: 0 failures" plus
`hostmatch PASS` only if every case matches the rule
above. This is the wildcard verification that can run
in this sandbox: guest DNS over slirp UDP is blocked,
so a live wildcard-SAN handshake cannot run here; the
end-to-end case awaits a peer-harness TLS proxy test).

## Try it (QEMU slirp)

```
./scripts/run_qemu.sh        # or: qemu-system-x86_64 -cdrom build/nxtsOS.iso -boot d -m 128 \
                             #   -netdev user,id=n0 -device e1000,netdev=n0
nxts> dhcp
nxts> ping 10.0.2.2
nxts> http 10.0.2.2 /test.txt 18080     # host server on 127.0.0.1:18080
nxts> https 10.0.2.2 / 8443             # host TLS server on 127.0.0.1:8443
```

Slirp notes (environment, not kernel): slirp TCP
proxying to the host works; slirp UDP forwarding does
not work in this sandbox (outbound UDP is blocked with
EPERM, proven), so slirp DNS (10.0.2.3) answers with
ICMP net-unreachable even though the guest's query
bytes are exactly correct (proven by pcap). The
deterministic peer-harness suite
(`tests/qemu_test_net_peer.py`) covers DNS strictly
without slirp.

## NOT implemented (re-checked against the post-v1.0.0 tree)

Two items from the v0.9.0 version of this list have shipped
since and are struck from it below, not silently dropped:
package signing shipped in v1.0.0 (NXPKG002, RSA-2048 —
see `docs/PACKAGES.md`), and graphical network settings
partially shipped in v0.10.0 (the desktop Network window
runs DHCP, sets DNS, and pings the gateway — see
`docs/DESKTOP.md`). What remains of the graphical-settings
gap is static IP configuration: there is no shell command
and no GUI control for it, only one-shot DHCP. The items
that are still genuinely unimplemented, each re-checked
against the code rather than carried forward:

User-mode socket API (networking is kernel stack +
shell commands only; no socket syscalls exist), TCP as a
general or multi-connection layer (one client connection
at a time, `net/tcp.c` header), IPv4 fragmentation
reassembly (fragments are dropped, `net/net.c`), DNS
CNAME following (CNAME records are skipped, `net/net.c`),
DNS over TCP (DNS goes out by UDP to port 53 only),
DHCP renewal and release (DHCP is one-shot; no
renew/release path exists), UEFI (BIOS multiboot via
GRUB; no EFI boot path).
