# nxtsOS web/SSL system — living design

> This is the living design document for the full web/SSL system (user commission 2026-10-28). It started as the pre-implementation draft; each phase appends its implementation notes below the original text instead of rewriting history.

## Phase 1 status (shipped in v1.1.3)

- CSPRNG: ChaCha20 DRBG (kernel/csprng.c) seeded from CMOS RTC + keyboard/mouse event timing + MAC uniqueness (NOT secrecy). No RDRAND assumption. xorshift survives only in window-manager test shuffles.
- CA store: root-owned system file castore.txt, one 512-hex-char RSA-2048 modulus per line (exponent 65537), blank lines and `#` comments skipped. Parsed on demand per connection, never compiled in. Store mode (`httpss`) ends the validated path at the first CA-store member, exactly like anchored mode ends at the pin.
- Store update: `castore add <file>` (root, manual; the file's first line must be the 512-hex modulus — a literal cannot be typed, the shell line buffer is 128 chars; a modulus already in the store is refused as "already present", never duplicated) or `castore update <host>` (root; fetches /castore.txt + /castore.txt.sig over anchored HTTPS, verifies the 256-byte vendor signature with the package trust anchors, then installs). No production bundle is published yet.
- Membership scan is windowed (1024-byte windows via fs_read_range_as, partial lines carried across windows), so a store up to the 65535-byte bundle cap verifies: the first windowed-scan draft used a whole-file 8192-byte read, which silently refused every store over ~15 roots — caught in review, fixed before the suite went green.
- TOFU prints: first accepted leaf per host is pinned in root-owned system file tofuprints.txt (`<host> <sha256-of-leaf-DER-hex>`); a different leaf later is a hard refusal. Diskless TOFU proceeds without recording (nothing to pin to); a mounted disk whose print file cannot be read or written fails closed.
- Commands: `httpss <host> <path> [port]`, `castore list|add|update|clear`, `tofprints list|clear` (root-only), `csprngtest` (RFC 8439 vector + monobit/zero/differ sanity).
- Honest limits carried forward: 4096-bit RSA verification still NOT IMPLEMENTED (termination avoids needing it for trusted roots/anchors; untrusted chains needing a 4096 verify before trust still refuse); bundle cap 65535 bytes (~127 roots hex); store format is RSA-2048 only (ECDSA roots arrive with Phase 2).

## Phase 2 status (shipped in v1.1.3)

- TLS 1.3 client (net/tls.c, "TLS 1.3 + TLS 1.2 client"): combined ClientHello offering 0x1301, 0xC02F, 0xC02B, 0x009C with SNI, supported_versions [1.3, 1.2], supported_groups [secp256r1], signature_algorithms [RSA+SHA256, ECDSA+SHA256, RSA-PSS+SHA256], key_share [secp256r1], ec_point_formats [uncompressed], ALPN [http/1.1]. ServerHello dispatch (legacy_version 0x0303, null compression, supported_versions + key_share extensions, 32-byte session-id echo); HKDF key schedule (early / handshake / master, c/s hs + ap traffic, derived secrets); AEAD reuses AES-128-GCM with per-epoch sequence numbers; EncryptedExtensions + optional CertificateRequest skip + Certificate (context must be empty, per-cert extensions skipped, leaf DER kept for the TOFU print) + CertificateVerify + server Finished (verified BEFORE it is appended to the transcript) + client Finished under hs keys, then application keys. No 0-RTT (replay risk). No PSK resumption in this phase. HelloRetryRequest is rejected fail-closed (the client offers secp256r1 + 0x1301, so a conforming server never sends one).
- ECDSA for TLS 1.2: P-256 certificate verification (net/ec256.c, host-verified against SEC2 vectors) and ECDSA ServerKeyExchange / ClientKeyExchange; suite 0xC02B (TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) offered and accepted. Note: 0xC00A was first offered under the mistaken label "ECDHE-ECDSA AES-128-GCM" — it is actually AES-256-CBC-SHA, which the GCM-only record layer cannot speak; corrected to 0xC02B everywhere before the suite went green (no existing test used 0xC00A).
- ECDSA roots in the CA store: a store/anchor line may now be `EC256:` followed by 130 hex chars (uncompressed P-256 point, must start with 0x04); RSA-2048 lines are unchanged. All three trust modes (TOFU / anchored / store) work over TLS 1.3 exactly as over TLS 1.2, with the same chain-termination rule (stop at the first store member/anchor; oversize keys that must actually be verified still refuse).
- Negotiation policy (non-negotiable, enforced): default offers TLS 1.3 + 1.2 ONLY; no legacy offered by default; a failed modern handshake never retries in legacy. Downgrade protection: a ServerHello with legacy_version below 0x0303 is refused; a TLS 1.2 negotiation whose server random carries the RFC 8446 DOWNGRD sentinel (last byte 0x00 or 0x01) is refused. The repo path stays modern-only anchored.
- CSPRNG wired into every new random need: client random, ECDHE private key (fresh per handshake, up to 4 generation attempts), session id. No xorshift anywhere in the new crypto path.
- Interop findings from the build (all fixed, all proven by bisection or host test, not by guessing):
  - TLS 1.3 servers (OpenSSL) refuse PKCS#1 v1.5 for CertificateVerify and require RSA-PSS: s_client with guest-like parameters fails with NO_SUITABLE_SIGNATURE_ALGORITHM unless rsa_pss_rsae_sha256 is offered. The guest now offers 0x0804 LAST (so TLS 1.2 servers keep picking PKCS#1, the long-verified path) and verifies PSS via new `rsa_verify_pss_sha256` (net/rsaverify.c: MGF1-SHA-256, salt derived from the padding, strict EM/trailer checks), wired into both the 1.3 CertificateVerify handler and the 1.2 ServerKeyExchange handler.
  - TLS 1.3 client Finished was first encrypted under application keys (epoch switch before the send); the switch now happens after the send, with a comment recording the bug.
  - HKDF-Expand-Label omitted the label's 1-byte length prefix (RFC 8446 7.3 HkdfLabel = len(2) || label_len(1) || "tls13 " || label || ctx_len(1) || ctx). Guest keys matched an identically buggy offline script but no real peer could decrypt anything — every server record failed AEAD in the guest AND in a known-good Python↔Python control. Fix: one byte inserted. Proof: the fixed pipeline decrypts a saved OpenSSL control capture end-to-end (EE, Certificate, CertificateVerify alg 0403, Finished with 32-byte verify_data).
  - RSA-PSS verification failed for ~half of all valid signatures: `rsa_verify_pss_sha256` never cleared the leftmost 8*emLen - emBits bits of DB after unmasking (RFC 8017 RSASSA-PSS-VERIFY step — the signer clears those bits of maskedDB, so the unmasked DB inherits the mask's top bits there). Whenever MGF1(H)[0] had its top bit set, DB[0] came out 0x80, the PS scan failed at once, and verification returned -1. Host test of the guest function against 20 fresh PSS signatures failed 9/20 before the fix and passes 20/20 after the one-line fix (`if (zero_bits > 0) db[0] &= 0xFF >> zero_bits;` after the XOR loop). This is why RSA TLS 1.3 boots failed at stage 3 (CertificateVerify) on one attempt yet succeeded on the next: different signature, different mask bit. EC (no PSS) and PKCS#1 v1.5 (no masking) were never affected.
  - Diagnostic red herring, recorded so it is not re-chased: `openssl s_server` omits the self-signed root from its Certificate message, so a probe against it showed a lone CA:false leaf that TOFU correctly refuses (stage 2). The Python peer sends the full chain. Not a guest bug.
- Tests: new `tests/qemu_test_tls13.py` + `tests/qemu_test_tls13_setup.py` (14 boots, port 12353): TLS 1.3 RSA + ECDSA chains in TOFU, store, and anchored modes; TLS 1.2 RSA + ECDSA fallback; expired / wrong-host / bad-signature refusals; TOFU fingerprint-mismatch refusal; legacy-only server refusal (downgrade-legacy); both DOWNGRD sentinel values refused. Result on the final Phase 2 ISO: **14/14 PASS** (peer-negotiated versions/ciphers recorded per boot). `tests/tls_peer_lib.py` SslPeer extended generally (min/max version + cipher params, negotiated recording; defaults preserve TLS 1.2 behaviour). Host test `tests/host_pss.c` covers the PSS path (build: gcc -fno-builtin -o /tmp/host_pss tests/host_pss.c net/rsaverify.c net/bignum.c kernel/sha256.c). Tampered-Finished negative PROVEN by new raw-peer test `tests/qemu_test_tls13_tampered.py` (hand-rolled TLS 1.3 server: valid SH + EE + Certificate + CertificateVerify, then a Finished with flipped verify_data bits): the guest fails exactly at stage 4 (CertificateVerify done, Finished failed), prints `https: failed`, fetches no body, no panic — **PASS**. Two test-authoring lessons from that test, recorded so they are not re-learned: (1) a server key_share extension carries a bare KeyShareEntry (69 bytes), NOT a shares-length wrapper (the wrapper is client-side only) — the wrapped form makes the guest's SH parser skip key_share and die in ServerHello parsing with no stage print; (2) a success check must match `https: \d+ bytes`, not the substring pair `https: ` + ` bytes` (the latter false-positives on `https: failed` plus the boot line `User program blob: N bytes`).
- Stage instrumentation kept (terse, permanent): file-scope `tls13_fail_stage` in net/tls.c (1 keys derived, 2 EncryptedExtensions done, 3 Certificate done, 4 CertificateVerify done, 5 server Finished done, 6 client Finished sent); on a 1.3 handshake failure the dispatcher prints `tls13: handshake failed at stage %d` to serial. All temporary diagnostics (decrypt-fail print, EE mtype print, intermediates hex print, hardcoded ECDHE keypair) were reverted before the suite went green; CSPRNG key generation is restored.
- Honest limits carried forward: TLS 1.3 HRR unsupported (fails closed); TLS 1.3 PSK resumption and 0-RTT NOT in Phase 2 scope by design; 4096-bit RSA verification still NOT IMPLEMENTED; tampered-Finished negative PROVEN (see below), tampered-CertificateVerify negative still not covered by a raw-peer test (the CV path shares the Finished test's flight machinery; a CV-tamper variant is a small extension of tests/qemu_test_tls13_tampered.py).

## v1.1.3 security fix (release security pass, 2026-10-29)

- DER parser integer wraparound (`net/tls.c` `der_tlv`): the bound check `pos + hl + vl > buflen` overflowed u32 for crafted Name lengths near 2^32 (e.g. 0xFFFFFFF0), handing callers a ~4 GiB length — a malicious server certificate could panic the kernel via the verify_chain memcmp or the subject-name walk. Fixed with wrap-proof subtraction-form bounds; retested by host test `tests/host_der_tlv.c` (11/11; the same test fails 3/11 on the vulnerable code) and QEMU test `tests/qemu_test_tls13_wrappedcert.py` (guest refuses exactly at Certificate parsing, stage 2, no panic, no body). Full report: `releases/v1.1.3/SECURITY_REPORT.md`.

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
