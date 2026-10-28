# nxtsOS web/SSL system — living design

> This is the living design document for the full web/SSL system (user commission 2026-10-28). It started as the pre-implementation draft; each phase appends its implementation notes below the original text instead of rewriting history.

## Phase 1 status (built, unreleased — see AUTONOMOUS.md)

- CSPRNG: ChaCha20 DRBG (kernel/csprng.c) seeded from CMOS RTC + keyboard/mouse event timing + MAC uniqueness (NOT secrecy). No RDRAND assumption. xorshift survives only in window-manager test shuffles.
- CA store: root-owned system file castore.txt, one 512-hex-char RSA-2048 modulus per line (exponent 65537), blank lines and `#` comments skipped. Parsed on demand per connection, never compiled in. Store mode (`httpss`) ends the validated path at the first CA-store member, exactly like anchored mode ends at the pin.
- Store update: `castore add <file>` (root, manual; the file's first line must be the 512-hex modulus — a literal cannot be typed, the shell line buffer is 128 chars; a modulus already in the store is refused as "already present", never duplicated) or `castore update <host>` (root; fetches /castore.txt + /castore.txt.sig over anchored HTTPS, verifies the 256-byte vendor signature with the package trust anchors, then installs). No production bundle is published yet.
- Membership scan is windowed (1024-byte windows via fs_read_range_as, partial lines carried across windows), so a store up to the 65535-byte bundle cap verifies: the first windowed-scan draft used a whole-file 8192-byte read, which silently refused every store over ~15 roots — caught in review, fixed before the suite went green.
- TOFU prints: first accepted leaf per host is pinned in root-owned system file tofuprints.txt (`<host> <sha256-of-leaf-DER-hex>`); a different leaf later is a hard refusal. Diskless TOFU proceeds without recording (nothing to pin to); a mounted disk whose print file cannot be read or written fails closed.
- Commands: `httpss <host> <path> [port]`, `castore list|add|update|clear`, `tofprints list|clear` (root-only), `csprngtest` (RFC 8439 vector + monobit/zero/differ sanity).
- Honest limits carried forward: 4096-bit RSA verification still NOT IMPLEMENTED (termination avoids needing it for trusted roots/anchors; untrusted chains needing a 4096 verify before trust still refuse); bundle cap 65535 bytes (~127 roots hex); store format is RSA-2048 only (ECDSA roots arrive with Phase 2).

---

Draft written 2026-10-28, before implementation, per the user's
structured-working rule (decide up front, write it down, then build).
Placed in docs/ by the Phase 1 build; the phase status above is
the current record, the text below is the original draft.

## Goal

nxtsOS talks to any web server, old or new, and handles any
certificate: trusted (CA store), anchored (pinned, repo), or
untrusted/self-signed (explicit trust-on-first-use). The default
path is modern and secure; legacy is a fenced fallback.

## Decisions (user, 2026-10-28)

- Protocols: SSLv2, SSLv3, TLS 1.1, TLS 1.2, TLS 1.3 — all covered.
  The user explicitly chose legacy inclusion after being told
  SSLv2/v3 are broken by design and TLS 1.1 deprecated.
- Scope default: the fetch-side web stack (kernel TLS + an HTTP
  layer that fetches any HTTPS site reliably). NOT an
  HTML-rendering browser — that is a separate project if wanted.
- "Random and non trusted PKI": a proper cryptographic RNG, plus
  self-signed/untrusted certificate handling, plus a CA store.

## Protocol matrix

- TLS 1.3 (new): new handshake, HKDF key schedule, AEAD
  (AES-128-GCM reused), ECDHE P-256, RSA + ECDSA certificates,
  SNI, ALPN http/1.1. 0-RTT: NO (replay risk). PSK resumption:
  phase 2 candidate, not phase 1.
- TLS 1.2 (exists): extend with ECDSA certificates.
- TLS 1.1 (legacy): like 1.2 but MD5+SHA1 PRF and explicit IVs.
  No SNI/ALPN offered in legacy negotiation; the hostname check
  still applies to whatever certificate arrives.
- SSLv3 (legacy): SSLv3 PRF (MD5/SHA1 halves), MAC-then-encrypt,
  CBC IV chaining (BEAST-vulnerable by design — hence
  legacy-only). No extensions.
- SSLv2: honest boundary — SSLv2 is a different handshake
  protocol (2-byte headers, no extensions, weak ciphers), and no
  surviving server is known to require a full SSLv2 session; every
  SSLv2-era server also speaks SSLv3. Phase scope is an
  SSLv2-compatible ClientHello for probing plus real SSLv3/TLS
  1.1 sessions. Full SSLv2 record-layer crypto only if the user
  names a concrete target server that speaks nothing else.

## Negotiation policy (the security core)

- Default (Web window, shell https, repo): offer TLS 1.3 + 1.2
  only. Legacy is never offered by default.
- No silent downgrade, ever: a failed modern handshake NEVER
  retries in legacy automatically. The user must explicitly
  re-run in legacy mode (shell flag, e.g. `https --legacy`, and
  a Web-window toggle that shows a permanent INSECURE LEGACY
  indicator). This kills POODLE-style downgrade attacks.
- Repo path: modern only, ALWAYS (anchored TLS 1.2/1.3). Legacy
  never applies to package fetches — package authenticity must
  not ride on broken crypto. (Packages are RSA-signed anyway,
  but transport stays modern.)
- Legacy mode is fetch-only: no package installs from legacy
  sources.

## Random (CSPRNG)

- Replace xorshift for ALL crypto use. Entropy from RTC + timer
  jitter + mouse/keyboard timing (RDRAND not assumed present on
  old hardware). Design: a seed pool stirred from multiple
  sources feeding a ChaCha20-based DRBG (or SHA-256 counter
  DRBG — implementation picks one). Non-crypto uses (tests,
  jitter) may keep xorshift. No fake "hardware RNG" claims;
  entropy sources documented honestly.

## PKI / certificates

- CA store: a root-owned file (same pattern as tlsanchors.txt)
  holding trusted roots, parsed on demand per connection (not
  compiled into the kernel — disk is 16 MiB and kernel memory is
  tight). Store updates must themselves be verified (existing
  package-signature mechanism or an anchored fetch — decided in
  implementation).
- Chain termination rule (generalises the v1.1.2 stop-at-anchor
  fix): verification walks the chain verifying signatures until
  it reaches a cert trusted by store membership or anchor pin,
  then accepts and ignores everything after it. This is what
  makes sent 4096-bit roots harmless in anchored AND store mode.
- Anchored mode: unchanged (pinned WR1 for repo) + the v1.1.2
  stop-at-anchor fix.
- TOFU mode: extended to all versions; first-use fingerprint
  stored per host in a root-owned file; a fingerprint mismatch
  is a hard refusal with a warning, never a silent re-trust.
- Self-signed: accepted in TOFU mode (this is the "non trusted"
  ask); never in anchored/store mode unless the self-signed cert
  IS the pinned anchor.
- On-device key/cert generation tool: phase 2 candidate, not
  promised.

## HTTP layer ("all the things used in web infra")

- Already present: TCP, DNS client, HTTP/HTTPS fetch, Web save.
- Add: redirects (3xx, capped hop count), cookies (basic jar,
  per-host scoping), chunked transfer encoding, content-length
  and connection-close bodies, user-agent/accept headers, URL
  parsing edge cases and percent-encoding.
- Explicitly OUT of this scope: HTML/CSS/JS rendering (browser),
  HTTP/2 (phase 2 candidate — multiplexing is a big lift),
  WebSocket (phase 2 candidate), serving sites from nxtsOS
  (separate project).

## Phases

1. CSPRNG + CA-store file format + generalised chain-termination
   rule + tests.
2. TLS 1.3 (handshake, HKDF, AEAD, ECDSA) + ECDSA for TLS 1.2.
3. Legacy: TLS 1.1, SSLv3, SSLv2-Hello; legacy gate + indicator +
   no-auto-downgrade; legacy peer-harness tests.
4. HTTP layer: redirects, cookies, chunked, header polish.
5. Full regression + adversarial security pass + release under
   the normal release rules (one version, archives, SHA-256,
   tag, test report, security report; no GitHub push).

## Tests

- Peer harnesses for every version (modern + legacy servers)
  and every cert case: trusted, anchored, self-signed, expired,
  wrong-host, bad-signature, 4096-bit root sent, anchor
  mismatch.
- Downgrade-attack tests: a legacy-only server must NOT be
  reached in default mode; legacy mode must show the indicator.
- CSPRNG statistical sanity (no overclaimed "randomness proofs").
- HTTP tests: redirect-loop cap, cookie scoping, chunked bodies.

## Honest limits (carry into release notes)

- Full SSLv2 session crypto: not planned (see above).
- 4096-bit RSA signature verification: still NOT IMPLEMENTED.
  The termination rule avoids needing it for trusted
  roots/anchors; untrusted chains that need a 4096-bit verify
  before reaching trust still refuse.
- HTTP/2, WebSocket, HTML rendering: out of this scope.
