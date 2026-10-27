# nxtsOS v1.0.0 — Security report

Third-party-style adversarial testing, as required after every release.
Exploitable findings were fixed and retested before shipping;
unexploitable limits are recorded honestly below. All suites below
were re-run for Phase 11.2 on the release line (ISO 3057db70… for the
full sweep; ISO b396192d… for the final re-verification of the
suites that touch the last two fixes). See TEST_REPORT.md for the
per-suite verdicts.

## 11.1a — Package signatures: all attacks refused

- Legacy unsigned package (NXPKG001): refused,
  "package is not signed (legacy format)".
- Wrong-key signed package: refused, "bad package signature".
- Tampered package (manifest byte flipped after signing, same
  length): refused, "bad package signature" — only the signature
  check can catch this, and it does.
- Manifest/blob attacks signed with the vendor key on purpose
  (bad hash, bad size, bad path, absolute path, self-dependency,
  dependency cycle, missing dependency, oversize): the signature
  passes, the specific check still refuses each one
  (defense in depth, verified).
- Keyring acceptance verified: a package signed with a keyring key
  installs only when the matching modulus is in root-owned
  `pubkeys.txt`; a non-root user cannot pre-create the keyring
  (`pubkeys.txt` is a system file) or overwrite a root-owned copy.
- Signature proves the signer, not safety: a signed package can
  still contain a malicious program. Installation is root-only,
  and that boundary is the control, not the signature.

## 11.1b — System updates and rollback: all attacks refused

- Bad bundle (one good package + one wrong-key package): refused
  atomically — the good package stayed at its old version and
  still ran; nothing was half-written.
- Good bundle with a deliberately awkward order (dependent first):
  installed in topological order, both packages ran.
- Upgrade then `sysrollback`: previous version restored and ran;
  a second `sysrollback` correctly reported no update to roll back;
  re-applying the same bundle was refused as already installed.
- Snapshot/rollback state files (`rollback.txt`, `rb_packages.txt`,
  `rb0`–`rb63`) are system files: a non-root user cannot
  pre-create snapshot state to poison a later rollback.

## 11.1c — Remote repository: all attacks refused, fail-closed

- Stale index (older than the stored version): refused,
  anti-rollback holds, and the stored newer index survived.
- Tampered index (one byte changed, original signature):
  refused, "index signature invalid".
- Wrong-key package with a correct index hash: refused on
  signature grounds.
- 404 / wrong file served in place of a package: refused on
  index-hash grounds (the HTTP client does not check status
  codes, so the hash check is the control that catches this).
- Stored index tampering buys nothing: it is re-verified on
  every use, and every package is hash-checked and
  signature-checked again before install.
- Transport is plain HTTP by design (see PACKAGES.md): the
  kernel TLS client has no public CA trust store, so HTTPS to
  a public host could not verify anything. Only signatures
  make a repository trustworthy. A repository URL is public
  by design.
- Limits: index anti-rollback relies on the publisher-managed
  monotonic version plus an intact stored index; a repository
  package must sit a little under the 132096-byte cap because
  response headers count against the download buffer; the
  client is single-connection HTTP/1.0 with no chunked encoding.

## 11.2 — Full review: every earlier suite green, plus a fresh pass

Re-run green: storage (8 corrupt-disk cases), Phase 5 (malformed
ELFs, syscall abuse, brute-force halt, malformed users.txt),
v0.4.1 (background jobs, persistent lockout), package security
(above), encryption (no plaintext on disk, superblock tamper,
wrong passphrase, tampered ELF), GUI (driver/WM edge cases,
pixel signature intact), desktop security (non-root save denied,
lock screen, malformed GUI syscalls), calculator (glyph '7',
exact colours), classic desktop, desktop10, desktop apps,
desktop10sec (invalid settings ignored, evil.txt sanitised,
oversize BMP refused), desktop web (DHCP, truncation),
desktop nonic (clean no-device report), network slirp, network
peer, TLS, network security (400-frame flood survived, DNS
loop fails cleanly, wrong-host / tampered / expired
certificates refused exactly 3 times).

### Fresh pass findings — fixed and retested

1. TCP stale-segment acceptance (REAL BUG, fixed): `tcp_rx`
   never validated the destination port, and the FIN branch
   accepted ANY bare FIN regardless of sequence number, so a
   delayed FIN from a previous connection could close a new
   connection mid-download and truncate it. Symptoms seen:
   an intermittent repository-fetch hash mismatch. Fixed:
   destination port must equal the local port, and a FIN is
   accepted only at the exact receive position. Verified by
   15/15 repository runs plus the full network suites.
2. Integer wraparounds (hardening, fixed): the repository
   index version and the repository URL port were accumulated
   without overflow checks, so a huge value could wrap into a
   small version or a valid-looking port. Both now refuse on
   overflow. The index is signature-verified before parsing,
   so this was defense in depth, not a bypass — but a wrap
   must never silently become a small version.
3. Test-harness flakes (NOT kernel bugs, fixed in the tests):
   QEMU monitor sendkey occasionally delivers a key twice,
   garbling commands; the repository and Phase 5 senders now
   verify the shell's echo and retype once on mismatch.
   Separately, two repository-test bugs (non-idempotent
   fixture setup; fetching against a stale server) were fixed.
   In every case the kernel failed closed correctly.

### Known limits (unexploitable or out of scope, recorded honestly)

- `fs_write_as` bitmap/directory commit is not atomic: if a
  disk write failed at exactly the directory-save step after
  the bitmap save, sectors could be orphaned. A guest program
  cannot trigger a targeted ATA write failure, so this is a
  robustness limit for real hardware faults, not an
  exploitable path. No journaling exists yet.
- No CA trust store: TLS chains must end in a self-signed
  root (TOFU). No revocation checking, no wildcard matching,
  no TLS 1.3 / ECDHE / session resumption / client certs.
- RNG is timer-seeded xorshift, not cryptographic. Do not use
  the TLS client for real secrets yet.
- TCP ISN is predictable; `tcp_rx` destination-port validation
  is now done (fix 1 above), but the stack is still
  single-connection with no fragmentation reassembly, no DNS
  CNAME following, no DHCP renewal/release.
- Package trust has no key-add command and no revocation list.
  Rollback is one generation only and restores files plus the
  registry, not side effects of package programs.
- Disk encryption has no passphrase change, no recovery key,
  no authenticated encryption, and a non-memory-hard KDF.
- Real mouse movement/clicking was never delivered in QEMU
  (scripted injection only); VirtualBox and real hardware
  were never tested for any release.
