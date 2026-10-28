# nxtsOS v1.1.1 — Security report

Third-party-style adversarial testing, as required after every release.
Exploitable findings were fixed and retested before shipping;
unexploitable limits are recorded honestly below. All suites below
were re-run for v1.1.1 on the release ISO itself (no two-ISO story
this time); see TEST_REPORT.md for the per-suite verdicts.

## v1.1.1 — New surfaces reviewed

### TOFU chain rule (net/tls.c `verify_chain`): sound, with one honest note

The change widens what TOFU accepts, so it got the closest
review. What the code actually enforces, re-read line by
line (not carried from the fix run's notes):

- Dates are checked for EVERY certificate in the chain
  (loop over all `count` certs vs the CMOS RTC string),
  so an expired intermediate refuses exactly like an
  expired leaf.
- The leaf must match the requested host (`verify_host`
  on certs[0]: SAN DNS exact case-insensitive or
  single-label leading wildcard, never for IP literals;
  CN fallback only when no SAN exists).
- Every link verifies: each cert's issuer name must equal
  the next cert's subject (length + bytes), every
  non-leaf cert used as an issuer must be CA-flagged,
  and each cert's signature must verify with the next
  cert's RSA-2048 key. This is what refuses the bad-CA
  case (intermediate CA:false), the bad-signature case
  (same subject, different key), and any issuer/subject
  mismatch.
- Terminal: anchored mode is UNCHANGED (CA-flagged +
  pinned-anchor key match, else refuse). TOFU mode: a
  self-signed terminal keeps the old rule (CA-flagged +
  verifying self-signature); an intermediate terminal
  must be CA-flagged. Its own issuer's signature cannot
  be checked — the root is never presented — which is
  exactly what TOFU means, and the code comment says so.
- The widening does NOT weaken the MITM posture in
  substance: old TOFU already passed ANY self-signed
  chain for the hostname (a MITM with their own
  self-signed cert passed), so a MITM with their own
  CA:true-terminated chain passes under the same
  first-use trust model, in the same way. TOFU proves
  self-consistency, host binding, and private-key
  possession (via the handshake itself) — and nothing
  more. Anchored mode and the repository's signature
  checks remain the content-trust root and are untouched.
- Honest note (precision, not a hole): a LONE
  non-self-signed CA:true certificate (count == 1,
  issuer != subject) is now accepted by TOFU, since no
  issuer is present to verify it against. Under the old
  rule it was refused. No attacker capability is gained:
  minting such a cert is no easier than minting the
  self-signed cert the old rule already passed, and the
  handshake still proves possession of the leaf key.
- Proven live, not just read: tls_chain 5/5 (chain-ok
  success; bad-CA, bad-signature, wrong-host, expired
  refusals), tls_ske BAD/GOOD (wrong ServerKeyExchange
  signature refused with no ClientKeyExchange sent),
  tls_anchor 3/3, tls_peer wildcard + CN cases, and the
  full network security suite (wrong-host / tampered /
  expired certificates refused exactly 3 times).

### Desktop fallback dispatch (kernel/wm.c): sound

The fallback now dispatches on `desk_active` (desktop ->
full `desk_redraw()`, classic -> `wm_redraw()`). The
classic path is preserved for non-desktop UI; the
forward declaration + tentative definition merge legally
with the initialised definition in the desktop section.
The mode-30 test proves the desktop branch is taken in
the desktop loop (saved cursor position, Classic
background, zero green pixels, Web window present), and
all desktop suites (classic, desktop10, apps, web,
nonic, security, 10sec) plus storm pass on the release
ISO, so no classic-mode regression hides behind the
dispatch. No privilege or trust boundary is crossed: the
redraw only repaints already-visible UI state.

### Console present paths (kernel/console.c): sound

`console_putchar`'s fast path now presents the old + new
8x16 cursor cells after drawing them, each guarded by
ROWS/COLS bounds; in direct mode (no back buffer)
`fb_present_rect` is a no-op, so non-desktop behaviour
is unchanged. The change touches output only: keyboard
input, password reading (echo off), and login paths are
untouched, which is consistent with the passwd re-run
evidence (one isolated garbled current-password entry,
then a clean PASS on a fresh setup — see TEST_REPORT.md).
Proven live by shell_echo on both boots (plain shell +
desktop -> Terminal-exit path).

### Shell dispatch change (kernel/shell.c): no trust impact

The shell.c diff is help text (the new
`desktopfallbacktest` name) plus the dispatch line for
it. No command, permission check, or parser behaviour
changed. The full-shell help audit (dispatched == help)
is not re-run here because the only help-text change is
the added test-command name itself; the desktop10sec
suite (which exercises help-adjacent paths) passes.

## Re-run security suites (all PASS on the release ISO)

Storage security (8 corrupt-disk cases), Phase 5 security,
v0.4.1 security (persistent lockout), package security
(signature + manifest attacks), encryption security (no
plaintext, superblock tamper, wrong passphrase, tampered
ELF), GUI security, desktop security, desktop10 security,
network security — all PASS. `check_source.py` reports
FAIL only for the two pre-existing `logs/ske-test/`
artefacts (test-output files from the tls_ske suite),
the same expected lines as every prior chunk; no new
source-tree artefact from this release.

## Carried limits and known non-blockers (unchanged from v1.1.0)

- Shell `dhcp` / `dnsset` and Network-window DNS Set have
  no uid gate (pre-existing since v0.9.0): any logged-in
  local user can change global DNS. Repo/TLS verification
  does not depend on DNS alone (index signature + package
  hash + package signature, anchored mode for repo HTTPS).
- xorshift RNG is NOT cryptographic (weakest link;
  password salts are not secret, but session/token
  unpredictability must not rely on it). TCP ISN still
  predictable (destination-port validation IS done since
  11.2). FS bitmap/dir commit is not atomic (needs a real
  ATA write failure at one exact sector; a guest program
  cannot trigger it). One snapshot generation for rollback
  only; rollback restores files + registry, not program
  side effects. Near-max packages can fail repo fetch
  (headers count against the download buffer). Index
  anti-rollback relies on publisher-managed monotonic
  version + intact stored index.
- TLS 1.2 only; no TLS 1.3, resumption, client certs, or
  revocation; no general CA store, no 4096-bit RSA
  verification; ECDSA server certificates unsupported
  (server side must be RSA); ServerHello ALPN is offered
  but not parsed (client speaks HTTP/1.1 regardless).
- Package signing: no key-add command, no revocation list.
  Updates: one snapshot generation only.
