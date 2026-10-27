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
  be our IP or broadcast. UDP dispatch by destination
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
  Content-Length; chunked Transfer-Encoding is refused;
  body cap is the caller's buffer (the shell passes
  8192 bytes — a 5001-byte body fetches fine).

## TLS 1.2 client (`net/tls.c`, `net/bignum.c`)

One cipher suite only: TLS_RSA_WITH_AES_128_GCM_SHA256
(0x009C), RSA key exchange, TLS 1.2 only. The handshake
was verified against real OpenSSL (s_server and a
python `ssl` server): ClientHello (SNI +
signature_algorithms extensions — OpenSSL 3 servers
reject hellos without the latter), ServerHello,
Certificate, ServerHelloDone, RSA-encrypted premaster
(PKCS#1 v1.5 type-2 padding, non-zero random bytes),
master secret and key block via the TLS PRF (P_hash
with SHA-256), ChangeCipherSpec, Finished both ways,
then AES-128-GCM app data (nonce = write_IV ||
sequence, AAD = sequence || type || version ||
length, tag verified before decrypting).

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
matching is SAN-only when SANs exist (DNS exact
match, case-insensitive, **no wildcards**; IP hosts
match SAN IPs), CN fallback only when no SAN exists.
Certificate failure returns -2 and the shell prints
"certificate refused, connection not made"; every
other failure returns -1 ("https: failed").

**What TLS here is NOT (read before deploying
anything against it):**

- **No CA trust store ships.** A chain must terminate
  in a self-signed root whose signature verifies with
  its own key, whose dates are valid, and whose leaf
  matches the requested host. That proves
  self-consistency, host binding, and private-key
  possession — it is trust on first use (TOFU), NOT CA
  authentication. A man in the middle with their own
  self-signed certificate for the same hostname would
  also pass. A provisioned anchor store is future work.
- **Randomness is a timer/MAC-seeded xorshift32, NOT
  a cryptographic RNG.** This is the release's weakest
  link: premaster secrets, ClientHello randoms and the
  TCP ISN (ticks * 0x9E3779B9 ^ 0x12345678) are
  predictable to anyone who can observe timing. Fine
  for lab tests, NOT for real secrets.
- No ECDHE, no session resumption, no ALPN, no client
  certificates, no revocation checking, no TLS 1.3.
  GCM tag comparison is not constant-time (the tag is
  not a secret key, and this is a lab client).

## Shell commands

`netinfo` (MAC, rx/tx/drops, config), `netdbg`
(register + descriptor dump — the diagnostic that
found the register-offset bug), `dhcp`, `ping <ip>`
(dotted quad only), `dns <name>`, `dnsset <ip>`
(override the DNS server, e.g. for testing),
`http <host> <path> [port]`,
`https <host> <path> [port]`, `nettest` (10
malformed-frame injection cases through
`net_rx_frame`; prints `nettest PASS` only if every
case is dropped cleanly and nothing faults).

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

## NOT implemented in v0.9.0

User-mode socket API (networking is kernel stack +
shell commands only), graphical network settings,
TCP as a general or multi-connection layer (one
client connection), IPv4 fragmentation reassembly,
DNS CNAME following, DNS over TCP, DHCP renewal and
release, package signing (unchanged), UEFI
(unchanged).
