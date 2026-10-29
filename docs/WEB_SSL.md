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

## Phase 3 status (legacy TLS 1.1 + SSLv3 + SSLv2-Hello probe; SHIPPED in v1.1.4 — 2026-10-29)

- Scope (per the user's 2026-10-28 order and the design doc's rule): TLS 1.1 client, SSLv3 client, SSLv2-Hello probing ONLY. Full SSLv2 session crypto is OUT — no concrete SSLv2-only target server has been named, and every SSLv2-era server also speaks SSLv3. ECDHE-CBC is deferred (handshake matrix stays 1 suite x 2 versions); client CertificateVerify is not needed (fetch servers never request client certs).
- One legacy suite: `TLS_RSA_WITH_AES_128_CBC_SHA` (0x002F), the canonical old-server suite; RSA key exchange reuses the existing premaster-encrypt path. New CBC record layer, separate from the GCM path; modern path untouched. TLS 1.1: AES-128-CBC + HMAC-SHA1, explicit CSPRNG IV per record, TLS padding with all pad bytes checked, 72-byte key block (no IVs). SSLv3: AES-128-CBC + SSLv3 MAC (pad1/pad2 construction, NOT HMAC) + chained IV (first IV from the 104-byte key block, then last ciphertext block), SSLv3 padding (length byte only). PRFs: TLS 1.1 MD5+SHA1 combined PRF; SSLv3 its own MD5/SHA1 construction (different labels/pads, randoms in opposite order for master vs key block). Finished: TLS 1.1 12 bytes (PRF over MD5+SHA1 of the transcript), SSLv3 36 bytes (MD5/SHA1 construction with CLNT/SRVR senders); server Finished verified BEFORE appending, same discipline as 1.3. No close_notify in legacy mode (TCP close is the teardown); no DOWNGRD-sentinel check in legacy mode (explicit user consent to weak crypto; the sentinel is a modern-path protection).
- New crypto, all host-tested against published vectors before use: `kernel/md5.c` (RFC 1321), `kernel/sha1.c` (FIPS 180-1), `aes128_decrypt`/`aes256_decrypt` in `kernel/aes.c` (FIPS-197 + Python cross-checks). Host suite `tests/host_legacy_crypto.c` (21 checks: MD5/SHA-1 vectors incl. 1,000,000-byte input, AES decrypt vectors + roundtrips, cross-check hashes, RSA-SHA1 verify + flipped-signature negative) — **PASS**. No MD5/SHA-1 existed in-tree before Phase 3; no xorshift anywhere in the new crypto path (CSPRNG for client random, premaster, explicit IVs, probe challenge).
- Certificates: shared `parse_cert` + `verify_chain` + TOFU machinery; legacy adds sig_alg 2 = RSA/SHA-1 (OID 1.2.840.113549.1.1.5, outer + inner) verified by `rsa_verify_sha1` (PKCS#1 + SHA-1 DigestInfo), GATED on legacy mode — modern mode refuses SHA-1 certs exactly as today (proven by the sha1-default boot).
- Opt-in (per connection, explicit, single-use): shell flag `https [--legacy] <host> <path> [port]` on https/httpsa/httpss (same flag on all three trust modes); Web-window Legacy toggle button (Fetch row: status text x+130 -> x+240, toggle x+120..230, Fetch coordinates UNCHANGED so existing desktopwebtest clicks still land; every legacy fetch's status line carries a permanent "INSECURE LEGACY: " prefix until the next fetch). Mechanism: `tls_set_legacy_once()` consumed (cleared) at handshake start inside `https_get_inner` AND cleared by the shell/Web caller after the call returns — a stale flag can never leak into a later connection (proven by the flag-consumed boot), and the repo path (no legacy option on `pkg repo`/`update`/`fetch`) stays modern-only anchored by construction.
- Negotiation, fail-closed both ways: legacy hello = version 0x0302, suite [0x002F], null compression, NO extensions (no SNI/ALPN; hostname check still applies). ServerHello 0x0302 -> TLS 1.1 path; 0x0300 -> SSLv3 path; anything else (including a 0x0303 modern answer) -> hard refusal with `legacy: refused ServerHello version 3.3 (use default mode)`. Legacy mode never silently upgrades; default mode never silently downgrades (default still offers 1.3+1.2 only; a legacy-only server is refused in default mode). Note: pre-negotiation 0x0303 records are passed up to the ServerHello dispatch (not dropped at the record layer) SOLELY so the dispatch can print that refusal; once negotiated, the record version is enforced exactly.
- SSLv2-Hello probe: new net-group command `sslprobe <host> [port]` (flat + `net sslprobe` via group dispatch, dedicated help entry): sends an SSLv2-format ClientHello (2-byte header, version 0x0200, CSPRNG challenge), classifies the reply (SSLv2 SERVER_HELLO / TLS ServerHello version / alert / timeout), closes WITHOUT establishing any session.
- Tests: new `tests/qemu_test_legacy.py` + `tests/qemu_test_legacy_setup.py` (19 boots, port 12354): TLS 1.1 + SSLv3 fetches (negotiated version/suite + premaster version asserted per boot), SHA-1 gate open in legacy / shut in modern, legacy-only refused in default mode, modern ServerHello refused in legacy mode, expired / wrong-host / bad-signature / tampered-Finished legacy negatives, store + anchored + TOFU-mismatch legacy modes, flag consumption, and 5 sslprobe classifications (SSLv2-hello / TLS / alert / silent / group dispatch). Result on the final Phase 3 ISO (5,455,872 B, sha256 `401cef77b668faa5a38579c5e51fd996c6c9157306f12c1c47b198bbac83684d`): **19/19 PASS**. Neighbours on the same ISO: all TLS suites (tls, tls_chain, tls_anchor, tls_anchor_stop, tls_ske, tls_ecdhe, tls_peer, tls_hostmatch, tls_alpn, tls13 14/14, tls13_tampered, tls13_wrappedcert, castore 10/10) + desktop, desktop10, desktop_apps, desktop_newapps, desktop_web, shell_groups, sec_desktop — **20/20 PASS**.
- Bugs found by the suite and fixed in this run (all with genuine pre-fix FAILs, none papered over): (1) SHA-1 DigestInfo prefix ended `0x10` (MD5's 16-byte length) instead of `0x14` (SHA-1's 20 bytes) — every genuine SHA-1 signature failed; fixed in `net/rsaverify.c`, proven by host verify on the real cert and by a fixed-vector host check that FAILs on the old prefix. (2) Hand-rolled SSLv3 peer used the client IV for server records and vice versa (test bug, kernel correct) — fixed in the peer. (3) Python `ssl` refuses even to LOAD a SHA-1 chain at default security level — the sha1-default boot's peer now uses a parameterised `seclevel0` flag in `SslPeer` (default behaviour unchanged). (4) Record layer dropped 0x0303 records before the ServerHello dispatch could print the designed refusal — fixed as described above.
- Honest limits carried forward: legacy peers are hand-rolled (this sandbox's OpenSSL 3.0.13 cannot serve TLS 1.1 — `s_server -tls1_1` fails at default SECLEVEL and dies in `tls_choose_sigalg` at SECLEVEL=1 — and no real SSLv3 server exists here); residual self-agreement risk is mitigated by published-vector host tests + independent peer implementations on hashlib/hmac/cryptography, and by the TLS 1.1 framing being identical to the proven TLS 1.2 path except the version byte + suite list. The Web Legacy toggle button CLICK itself is NOT TESTED in QEMU (no click helper delivers PS/2 packets in this harness; the toggle shares the shell-proven `tls_legacy_once` mechanism, and its draw/click code is build-verified and reviewed). SSLv3 is broken by design (POODLE-class attacks, no modern use) — it exists here only for explicitly requested old-server fetches, labelled INSECURE on every fetch, never default, never for the repo. No constant-time crypto (carried weakness). Tampered-CertificateVerify negative still not built (same standing gap as Phase 2). NOT TESTED: live Vercel fetch; Bochs; real hardware; user retests; legacy against a real old server.

## Phase 4 status (HTTP layer: redirects, cookies, chunked, header polish; SHIPPED in v1.1.4 — 2026-10-29)

- Architecture: new `net/http.c` + `net/http.h`. The raw single-request functions keep their EXACT contract (`net_http_get`, `net_https_get`/`_anchored`/`_store`: one request, no redirects, no cookies) because the package repo and `castore update` call them — the repo takes no part in redirect/cookie behaviour changes. New wrappers `net_http_fetch` / `net_https_fetch(mode, ...)` are used by the shell fetch commands and the Web window (`desk_web_fetch`, TLS mode 0). The raw cores gained internal single-fetch variants (optional Cookie header in, store flag, status + Location out); public signatures unchanged. All large buffers are file-scope statics (16 KiB kernel-stack rule). `scripts/build.sh` gained `net/http.c` (compile + link).
- Request: HTTP/1.0 + Host + `User-Agent: nxtsOS` + `Accept: */*` + `Connection: close` + Cookie only if the WHOLE header fits (cookie header built into a 512-byte static; request into a 1024-byte buffer; omitted whole, never partial).
- Response parsing (one shared helper, replacing the ad-hoc scans in `net/net.c` + `net/tls.c`): status line 3-digit parse (malformed -> fail); header block cap 4096 bytes (over -> fail); header names case-insensitive, value = after ':' trimmed; Content-Length: every value parsed with overflow check, conflicting duplicates -> fail, identical duplicates -> first wins; Transfer-Encoding must be exactly "chunked" (case-insensitive) else fail; Content-Length + chunked together -> fail (ambiguity); Location: first wins; Set-Cookie: every line parsed when storing enabled.
- Body: Content-Length -> first N bytes (existing truncate-and-drain kept); chunked -> in-place decode (decoded <= encoded, forward copy safe); close-delimited -> rest. Chunked rules: hex size, ';' extensions ignored, trailers skipped to blank line or EOF; incomplete chunk at end of stored data + truncated flag -> partial body + truncated reported; incomplete + clean close -> malformed -> fail; bad hex / bad CRLF / size overflow -> fail.
- Redirects: statuses 301/302/303/307/308 with Location only (other 3xx pass through as bodies; GET-only client, so all five re-GET trivially). Max 5 hops (6 requests); loop = repeated URL in the chain -> refuse BEFORE re-fetching. Resolution: absolute URL (scheme/host[:port]/path, fragment stripped, userinfo -> refuse), scheme-relative `//host/path`, absolute path, relative path (dir merge + `./` and `../` collapsing). Cross-host allowed. Port defaults 80/443; explicit port outside 1..65535 -> refuse. `--no-redirect` -> distinct return -4 + "redirect not followed: <target>" via the last-error string.
- Security (non-negotiable, proven by tests): https->http downgrade refused BEFORE fetching ("redirect refused: https to http downgrade"); http->https allowed (upgrade). The legacy flag is per-request, consumed on hop 1 only, NEVER re-armed across redirects — a redirect to a legacy-only target fails its modern handshake; proven by recording the hop-2 ClientHello (modern 0x0303 offering 0x1301, not legacy-only 0x002F). Cert refusal (-2) on any hop propagates. The hostname check still applies on every hop. Secure cookies only over TLS; cookies never sent to a host outside the cookie's domain. The repo path is untouched (raw functions, no wrapper).
- Cookies: jar 16 entries, memory-only (no persistence across reboots, by design), file-scope statics. Set-Cookie parse: name=value; attributes case-insensitive: Path (default = request directory), Domain (absent = host-only exact; present = suffix match, leading dot stripped; Domain not a suffix of the response host -> refused), Max-Age (seconds x 100 ticks, overflow-clamped; <=0 -> delete; absent -> session cookie, lives until reboot/clear), Secure (sent only over TLS). Caps: name 63, value 127, domain/path 63 — overlong -> cookie refused, never truncated. Matching: domain (host-only exact or suffix), path (equal, or prefix ending at a '/' boundary), Secure -> TLS only, expiry (ticks >= expiry -> skipped; expired pruned on list). Jar full -> oldest evicted (insertion sequence). Management: `cookies list|clear` (net group, flat + `net cookies` dispatch, dedicated help entry).
- Shell: http/https/httpsa/httpss gain leading `--flags` in any order via ONE shared helper `parse_fetch_args` (replaces the three duplicated `--legacy` shifts + the http port parse): `--legacy` (TLS only; http rejects it), `--no-redirect`, `--no-cookies`. Usage strings updated; unknown flag -> Usage. Port parsing keeps the old lenient rule (an invalid port word leaves the default). Failure printing: cert-refused first, then the last-error string (policy refusals), then generic failed. Wrapper returns: final body length, -2 cert refused (any hop), -4 redirect not followed, -1 generic; policy reason via `net_http_fetch_error()`. Web window: wrapper calls, status/cert messages unchanged, policy reason added to the console line on failure.
- Tests: host suite `tests/host_http.c` — **43/43 PASS** (status/headers/CL/TE/chunked/cookies/resolver; build `gcc -fno-builtin` + `kernel/util.c` for the string functions, same pattern as the legacy host suite; two initial failures were test bugs — wrong chunk size in the basic chunked case, an overflow case that actually fit — fixed in the test, kernel untouched). QEMU suite `tests/qemu_test_http.py` + `tests/qemu_test_http_setup.py` (port 12355, TLS fixtures: CA + leaf for http.test, chain `chain-http.pem`; HTTPS boots use diskless TOFU): 23 boots (plain: redirect, multi, loop, limit, crosshost, relative, cookie-main, cookie-edge, chunked, chunkbad, chunktrunc, header-case, dupcl, bigheader, noredirect, nocookies, flag-order; TLS: https-redirect, https-cookie, https-chunked, https-crosshost, https-downgrade, https-legacy-target) — **23/23 PASS in one run** on the final Phase 4 ISO (5,472,256 B, sha256 `f469ee176477b5a2ff1798b1ffe28ada096238f67868c89a01f404fe71141a12`, kernel 349,008 B). Peers: `PlainPeer` (`NetPeer` subclass, guest TCP port 80, raw routes, request recording, FIN after response so chunked/close-delimited readers terminate); `SslPeer` extended ADDITIVELY in `tests/tls_peer_lib.py` (`raw_routes` = path -> complete response bytes, `requests` = (path, raw request) per connection, `table` = servable paths; defaults unchanged); `NetPeer` TCP-port parameterisation (default 443); `DualPeer` (`SslPeer` subclass: connection 0 serves the redirect, connection 1 records the full ClientHello — waits for the complete first record — then sends a fatal alert `15 03 03 00 02 02 28` and FINs, so the test proves hop 2 attempted a modern handshake). DNS in the peer answers EVERY A query with the peer IP, so other.test also reaches the peer. Distinct markers per step within a boot are required because the harness `wait_for` checks the full serial log, not fresh output (repeated identical markers break sequencing).
- Failures diagnosed in the suite runs, none a kernel bug: (1) run 1 cookie-main: QEMU monitor sendkey doubling typed `/seet` instead of `/set`; the harness retry ran the correct command and all markers were found, but the spurious 404 request broke the exact-count assertion — clean re-run PASSED with exactly [/set, /check, /check2]. (2) run 1 + re-run https-crosshost (twice): TEST-fixture bug — the leaf SAN covered only http.test, so hop 2 to other.test was (correctly) refused on hostname mismatch; the guest behaved right, the fixture was wrong. The single shell line "certificate refused" can come from ANY hop, not just hop 1 (the re-run peer log showed exactly one request, [/hxhost], proving hop 1 served the redirect and hop 2 never sent an HTTP request). Fixed: setup now issues SAN `DNS:http.test,DNS:other.test` (documented in the setup file and the test docstring); re-run PASSED ([/hxhost, /xhosted], Host: other.test) and https-redirect still passed on the new cert. (3) run 2 redirect (`//redir`), cookie-edge (`/setseccure`), https-chunked (`/hchunkk`): all the same sendkey-doubling class, each visible as a mistyped command in its serial log, each with all markers found on retry. Test-only fix, principled not a weakening: `reqs()` now filters the peer request log to KNOWN routes (paths in `peer.table`); a mistyped command fetches an unknown path, gets a 404, and is filtered out. This preserves real-bug detection because every real redirect/cookie bug changes the KNOWN-path sequence (missing expected path, repeated path, or extra known hop), and those still fail. Also fixed in the suite harness: `send_text` echo detection — the legacy check `"root@nxts> <cmd>"` can never match a slice taken after the prompt was already printed, so every command was typed twice; the new check matches command text + newline (exact against doubling, since a doubled letter breaks the `"\n"` adjacency). The smoke boot after this fix ran in ~12.5 s (vs ~48 s before) with exactly [/redir, /final].
- Neighbours on the same final ISO (fresh workdirs under `~/workspace/nb-work/p4-neighbours`, sequential, runner `run-p4-neighbours.sh`; Phase 3's neighbour results predate this ISO and do NOT stand for Phase 4): host legacy crypto PASS + legacy **19/19 PASS** + all TLS suites (tls, tls_chain, tls_anchor, tls_anchor_stop, tls_ske, tls_ecdhe, tls_peer, tls_hostmatch, tls_alpn, tls13 **14/14**, tls13_tampered, tls13_wrappedcert) + castore **10/10 PASS** (store-good/nostore/wrong/badsig/oversize/big, tofu-print, csprng, update-good/update-badsig) + desktop, desktop10, desktop_apps, desktop_newapps, desktop_web, shell_groups, sec_desktop — **23/23 neighbour suites PASS, zero failures**. The `SslPeer.table`/`raw_routes` addition is additive, and the tls13/legacy neighbours passing on this ISO is the proof it did not break them. Incidents during neighbours: a VM replacement wiped QEMU mid-run (first attempt aborted at the legacy suite with `qemu-system-x86_64` not found; host suites had already passed); toolchain restored via the apt fallback (cached deps + `apt-get install -f` repair of three half-configured packages + `apt-get install qemu-system-x86` -> QEMU 8.2.2, ISO re-verified f469ee17… unchanged) and the neighbour run restarted from scratch. A runner bug found by that abort and fixed (test-infra only): `set -e` exits at the first failing command inside a function even when the next line captures `$?`, so the legacy FAIL line was never recorded (proven by a small repro) — the runner now has no `set -e`; each run function echoes its line then aborts explicitly.
- Build notes: build GREEN, exit 0, no errors, 6 pre-existing warnings only. Freestanding-kernel gotcha encountered: no `NULL` (no stddef) — use `0` for null pointers in kernel code (fixed in `net/http.c`, `net/net.c`, `net/tls.c`); one stray closing brace left in `net/tls.c` after the tail replacement was removed.
- Deliberately OUT (unchanged scope): HTTP/2, WebSocket, HTML rendering; Expires-date parsing (Max-Age only — an Expires attribute is ignored, cookie becomes session); cookie persistence across reboots (jar is memory-only); proxy support; 300/304/305 special handling (pass through as normal responses); HTTP server (fetch-side client only).
- NOT TESTED (carried forward, plus Phase 4's own): Phase 4 against real web servers (peers hand-rolled); cookie persistence across reboots (memory-only jar by design); live Vercel guest fetch from the kernel (peer-harness proof only); user-side Virt-Manager retests (v1.1.2 repo commands, desktop fixes, Phase 2 TLS 1.3, v1.1.3); Bochs re-run for v1.1.x trees (last Bochs pass was v0.10.0); real-pointer mouse movement/clicking (scripted injection only); real hardware; tampered-CertificateVerify negative (not yet built); legacy vs a real old server (hand-rolled peers); Web Legacy toggle click itself.

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
