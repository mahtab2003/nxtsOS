# nxtsOS v1.1.4 — Release manifest

- Version: 1.1.4 (accumulation release over v1.1.3: web/SSL
  Phase 3 legacy protocols + Phase 4 HTTP layer)
- Date: 2026-10-29
- Kernel: original 32-bit x86 monolithic kernel, Multiboot 1 via GRUB.
  No Linux code, no distro, no fork, no re-theme.
- ISO: `nxtsOS.iso`, 5,472,256 bytes,
  SHA-256 `a2a4dbae29bf545274217dd693a9a1cf45463bfef53103014e0ec3865432114e`
- Kernel binary: `build/nxtsOS.bin`, 349,008 bytes (at build time)
- Distribution contents: `nxtsOS.iso`, `calc.nxpkg`,
  `term.nxpkg`, `run_qemu.sh`, `bochsrc.txt`,
  `mkdisk.py`, `VM_GUIDE.md`, `BUILD_AND_TEST.md`, this manifest,
  `TEST_REPORT.md`, `SECURITY_REPORT.md`, `README.md`, `VERSION`,
  `SHA256SUMS` (SHA-256 of the ISO inside the dist folder).
- Source archive: the full source tree minus `build/`, `archives/`,
  `logs/`, `.git`, plus this release's three documents.
  The package signing key (`build/signing.key`) never ships in any
  archive. The compiled-in vendor public key ships as generated
  source (`kernel/vendor_pubkey.h`) so vendor-signed packages verify.
- Git: branch `main`, tag `v1.1.4` (local only; no GitHub push —
  the user did not authorise a push for this release).
  The exact commit hash is recorded in the delivery notes, not inside
  this manifest, because the manifest itself is part of the commit.
- Tested on: QEMU 8.2.2 (serial + VNC suites) — see
  TEST_REPORT.md. Bochs 2.7 was NOT re-run for v1.1.4
  (last Bochs pass: v0.10.0); see TEST_REPORT.md.

## What is in v1.1.4 (over v1.1.3)

- Web/SSL Phase 3: TLS 1.1 + SSLv3 client (single suite
  TLS_RSA_WITH_AES_128_CBC_SHA), new CBC record layer
  (TLS 1.1: AES-128-CBC + HMAC-SHA1, explicit CSPRNG IV
  per record, full pad-byte checks, 72-byte key block;
  SSLv3: AES-128-CBC + SSLv3 MAC pad1/pad2, chained IV,
  104-byte key block); TLS 1.1 MD5+SHA1 PRF and SSLv3's
  own MD5/SHA1 construction; new crypto `kernel/md5.c`,
  `kernel/sha1.c`, AES decrypt. SHA-1 certificates gated
  to legacy handshakes only (modern mode still refuses
  them exactly as before; one real kernel bug found and
  fixed in this phase: the SHA-1 DigestInfo prefix ended
  `0x10` instead of `0x14`). SSLv2-Hello probe command
  `sslprobe` (net group, dedicated help entry) classifies
  replies without establishing a session. Opt-in per
  connection only: `--legacy` flag on `https`/`httpsa`/
  `httpss` + Web Legacy toggle (every legacy fetch
  labelled INSECURE LEGACY); single-use flag consumed
  at handshake, never carried across requests; default
  still offers TLS 1.3 + 1.2 only; no silent downgrade
  either way; the package repo stays modern-only
  anchored by construction (it takes no legacy option).
  Full SSLv2 session crypto and ECDHE-CBC deliberately
  out. See docs/WEB_SSL.md.
- Web/SSL Phase 4: HTTP layer in `net/http.c` (shared
  response parser: 3-digit status, 4096-byte header cap,
  case-insensitive names, Content-Length duplicate/
  overflow rules, Transfer-Encoding must be exactly
  `chunked`, CL+chunked refused; chunked decoding with
  hex sizes, extensions ignored, trailers skipped,
  truncated vs malformed distinguished; 16-entry
  memory-only cookie jar; redirect resolver for
  301/302/303/307/308, max 5 hops, loop refusal,
  relative resolution). Shell `http`/`https`/`httpsa`/
  `httpss` gain leading `--flags` in any order via one
  shared parser: `--legacy` (TLS only; plain `http`
  rejects it), `--no-redirect`, `--no-cookies`; new
  `cookies list|clear` (net group, dedicated help
  entry). The raw single-request getters keep their
  exact contract (repo + `castore update` untouched).
  Security policies, all proven by tests: https→http
  downgrade refused before fetching; the legacy flag
  is consumed on hop 1 only and never re-armed across
  redirects (proven by recording the hop-2 ClientHello);
  cert refusal on any hop propagates; hostname check
  applies on every hop; Secure cookies never over plain
  HTTP. Deliberately out: HTTP/2, WebSocket, HTML
  rendering, Expires parsing, cookie persistence,
  proxy, HTTP server. See docs/WEB_SSL.md.
- Release-run test/harness fixes (no kernel behaviour
  change): `shell_groups` + `scroll` now read VERSION
  from the repo root instead of hardcoding `v1.1.3`;
  `user` prompt check requires `root@nxts> ` after the
  finish line; `host_pss` build gains `kernel/sha1.c`
  and vectors come from new `tests/gen_pss_vectors.py`;
  two new security harnesses (`tests/host_http_sec.c`,
  `tests/qemu_test_http_sec.py`).
- Security pass: no exploitable finding in the new
  surfaces (see SECURITY_REPORT.md for the full
  adversarial read, the two green harnesses, and the
  carried weaknesses).

## What is NOT in v1.1.4

- Live Vercel guest fetch from the kernel is still NOT TESTED
  (peer-harness proof only). User-side Virt-Manager retests
  (repo commands, desktop fixes, Phases 2–4) remain the
  key live proof.
- 4096-bit RSA verification is still NOT IMPLEMENTED for links
  that must actually be verified.
- No TLS 1.3 PSK/0-RTT (out of scope by design), no graphical
  boot login, installer, UEFI, production CA bundle
  publication, package revocation list, multi-generation
  rollback, or HTML rendering.
- The tampered-CertificateVerify negative test is still
  NOT BUILT (standing gap from Phase 2; next plan item).
- Legacy against a real old server and Phase 4 against
  real web servers are NOT TESTED (hand-rolled peers only).
