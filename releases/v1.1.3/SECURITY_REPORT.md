# nxtsOS v1.1.3 — Security Report (adversarial third-party-style read)

Release ISO: `build/nxtsOS.iso`, 5,439,488 B,
SHA-256 `37563b592395162aff9c1a9c45901e236e4ac914e6a265968272f26bf46a44ef`
(kernel `build/nxtsOS.bin` 316,212 B). Scope: full diff vs v1.1.2
(42 files, +4443/−363), read surface by surface. Method: manual
adversarial review of every changed file, plus targeted host and
QEMU tests for the one exploitable finding. No fuzzer was run;
the checks below are the reviewer's reasoning plus the tests named.

## Finding F1 (EXPLOITABLE — FIXED before shipping)

**DER parser integer wraparound (`net/tls.c` `der_tlv`).**
The bound check was `pos + hl + vl > buflen` in u32 arithmetic.
A crafted certificate Name length near 2^32 (e.g. 0xFFFFFFF0)
wraps the sum to a small value and PASSES, so `der_tlv`
returns a ~4 GiB value length to its callers.

Triggers, all from network-controlled certificate bytes:
- `verify_chain` memcmp(issuer, subject, issuer_len): a
  2-certificate chain whose leaf issuer and intermediate
  subject both carry matching huge Name lengths makes the
  guest read ~4 GiB past ~16 KiB buffers -> page fault ->
  kernel panic.
- `parse_name_cn` walk with a huge subject_len reads past
  the certificate buffer into adjacent static memory.
- The SPKI modulus/exponent strip loops (`bn_from_be`,
  exponent parse) also inherit the huge length; they are
  bounded once `der_tlv` lengths are genuine.

Reachability: any malicious TLS server, or a MITM serving a
crafted chain, during any `https`/`httpsa`/`httpss` fetch or
package-repo fetch. Remotely triggerable kernel panic (DoS).
No memory disclosure is claimed: the 4 GiB read faults
immediately on unmapped pages rather than leaking.

Fix (`net/tls.c` `der_tlv` only, wrap-proof subtraction
form): long-form header `n > buflen - pos - 2`; value
`hl > buflen - pos` then `vl > buflen - pos - hl`. Each
subtraction cannot underflow given the earlier checks
(pos < buflen, pos + 1 < buflen, hl <= 6). After the fix,
every successful `der_tlv` call guarantees
pos + hl + vl <= buflen in true arithmetic, so all
downstream lengths (issuer_len, subject_len, sig_len,
modulus/exponent lengths) are bounded by the real buffer
and all downstream paths are covered by construction.

Neighbour checks that ruled out sibling bugs:
- Signature/SPKI BIT STRING `vl - 1` uses are already
  guarded (`vl < 1` rejected at tls.c:467 and tls.c:540;
  EC point requires `bv == 66` exactly), so no underflow.
- `der_sig_to_rs` is strict (SEQUENCE tag, short or 0x81
  length only, exact length match, two INTEGERs with exact
  consumption, nonzero rlen/slen, 33-byte integers require
  a leading zero sign byte).

Retest for F1:
- New host test `tests/host_der_tlv.c` (verbatim `der_tlv`
  copy — `tls.c` cannot link standalone): 11/11 PASS on the
  fixed code; the same test against the vulnerable code
  FAILS 3/11 (wrapped 0xFFFFFFF0, 0xFFFFFF00, 0xFFFFFFFF
  all accepted). This is the deterministic pre-fix proof.
- New QEMU test `tests/qemu_test_tls13_wrappedcert.py`
  (Phase C suite `tls13_wrappedcert`): a raw TLS 1.3 peer
  serves a leaf whose subject Name length is 0xFFFFFFF0
  (outer/tbs lengths recomputed consistent, subject
  content and SPKI intact). On the release ISO the guest
  refuses EXACTLY at Certificate parsing ("tls13:
  handshake failed at stage 2"), fetches no body, and
  shows no EXCEPTION/PANIC/page fault. Pre-fix QEMU
  behaviour of this test was not measured (the pre-fix
  ISO was overwritten by the rebuild; the host test is
  the pre-fix proof).
- Full TLS suites on the fixed ISO (Phase B/C, final):
  Phase A tls PASS; Phase B anchor_stop, tls_chain,
  tls_ske, tls_anchor, tls_hostmatch, tls_alpn,
  tls_ecdhe, tls_peer, repo_https, repo_httpsa ALL
  PASS; Phase C castore 10/10 PASS, tls13 14/14 PASS
  (both downgrade sentinels refused), tls13_tampered
  PASS, tls13_wrappedcert PASS. No TLS suite
  outstanding. (The release gate item outstanding at
  report time is desktop_fallback, a proven harness
  race — see TEST_REPORT/AUTONOMOUS.md — not a TLS
  or security finding.)

## Surfaces reviewed, no exploitable findings

- **EC/PSS (`net/ec256.c`, `net/rsaverify.c`)**: schoolbook
  multiply fits u64 exactly (max sum 2^64−1), carry
  propagation complete; `n_inv` via a^(n−2) cannot borrow
  (P256_N low word 0xFC632551); ECDSA verify checks point
  validity, r/s nonzero and < n, one conditional
  subtraction each for e and x mod n (valid since both
  < 2n), infinity -> −1; PSS verify checks mod_len
  62..256, sig_len == mod_len, sig < mod, emLen ==
  mod_len, leading zero bits, 0xBC trailer, DB =
  PS||0x01||salt with salt length DERIVED, DB top-bits
  cleared after unmasking, H' recomputed and compared.
- **CSPRNG (`kernel/csprng.c`)**: ChaCha20 block is
  standard RFC 8439 (20 rounds, correct state layout,
  32-bit counter, 96-bit nonce); reseed uses three
  domain-separated SHA-256 outputs with lengths 86/88/87
  fitting the 88-byte input exactly; reseed on stir change
  or 1 MiB output (far below 2^32-block wrap). Stir is
  lock-free by design for IRQ context (keyboard/mouse):
  it only XORs a 32-byte accumulator and bumps a counter;
  a torn stir or lost increment cannot corrupt keystream
  state. `csprng_generate` runs only in process context.
  Self-test is vector + monobit + zero-block + differ
  sanity, NOT a randomness proof (as documented).
- **TLS 1.3 handshake (`net/tls.c`)**: SH dispatch checks
  all lengths before reads; suite 0x1301 + key_share
  present required; HRR magic rejected; legacy SH falls
  to the 1.2 allowlist with BOTH DOWNGRD sentinel values
  checked; EE requires total length match; Certificate
  requires context byte 0, exact bounds, cert_count < 4,
  exact end, nonzero count; CertificateVerify algorithm
  gated by leaf key type, blob built exactly (64 spaces
  + 33-char string + 0x00 + 32-byte hash = 130 bytes);
  server Finished length-exact and HMAC-verified BEFORE
  transcript append; client Finished sent under handshake
  keys with epoch switch only AFTER the send; master/app
  secrets derived after server Finished verification.
  `tls13_recv_record`: version 0x0303, length bounds,
  CCS only pre-encryption, encrypted records type 23
  len >= 16, GCM tag verified before any plaintext
  write, padding stripped as trailing zeros with inner
  type in {0x15, 0x16, 0x17}, sequence incremented only
  on successful decrypt. Transcript appends bounded by
  16384. `hkdf_expand_label` includes the length byte
  with a full bound check. `p256_ecdh` validates scalar
  AND peer point, infinity -> −1. GCM is standard
  bit-reflected multiply with u32 bit lengths (safe:
  cipher < 2^29 bytes).
- **Shell grouping/dispatch (`kernel/shell.c`)**: help
  word bounded with NUL termination; group print guards;
  pkg help combined buffer caps 62 < 64; pkg aliases
  preserve the root check and first-word-only rule;
  group dispatch rebuilds into a 128-byte line with caps
  and terminates (line strictly shortens per rewrite).
- **Desktop apps (`kernel/wm.c`)**: Calendar line buffer
  64 holds month + year + footers; `cal_dim` guards month
  range with leap handling; weekday math from 1970 with
  no underflow for realistic years; cell math max cell
  36 within the window; day-select click validates range.
  Stopwatch laps capped at 8, format output <= 15 chars
  < 24-byte buffer. Notes buffer 4096, lines capped at
  32 x 63 chars, empty lines skipped, save bounded,
  add rolls back on save failure, delete validates and
  reloads on failure. Launcher actions 18–20 dispatch via
  a simple if-chain; columns 1–2 unchanged.
- **Scrollback (`kernel/console.c`)**: ring index
  normalised to [0,100); view math keeps text_buf index
  < 25 rows; scroll clamps to [0, sb_count]; scroll only
  in fb_mode and when not suppressed.
- **Proc/IDT (`kernel/proc.c`, `drivers/idt.c`)**: kernel
  PD restored after the scheduler switch and before `sti`
  (correct placement); IDT prints CR3 on faults
  (diagnostic only).
- **Keyboard/mouse/enc/panic/vmm/e1000**: int key buffer
  carries KEY_PGUP/PGDN without truncation; release codes
  match neither make code; passphrase read ignores
  special keys (>= 0x100) instead of storing them;
  panic clears fb suppression and repaints first;
  vmm change is comment-only (entry 260 deliberately
  unshared, with the destroy_pd caveat documented);
  MAC stirred for uniqueness only, documented non-secret.
- **pkg/fs/users**: `is_system_file` extended to
  castore.txt + tofuprints.txt (prevents non-root
  planting of trust material); `fs_list` name padding
  capped at 32; `pkg_verify_vendor_sig` wraps
  `pkg_verify_sig` (same anchors — the documented
  store-updater design); user salts now come from the
  CSPRNG.

## Observations (NOT findings)

- DER integer sign-byte canonicality is not enforced: a
  32-byte r/s with the top bit set is accepted as a large
  positive. No forgery impact: values are range-checked
  (< n) and signatures are verified mathematically; a
  non-canonical encoding of a valid signature is still a
  valid signature, and certificate verification has no
  malleability concern.
- EncryptedExtensions other than length are not parsed
  (server-selected ALPN is ignored). The client only
  speaks http/1.1, so this breaks a fetch at worst, not
  a security hole.
- No socket read timeouts anywhere in the stack: a
  malicious peer sending endless empty records hangs the
  connection (liveness only, pre-existing class;
  transcript cap bounds the CertificateRequest loop).
- Comment-accuracy nit (not a finding): the group-dispatch
  comment claims "at most one rewrite", but crafted
  `fs fs fs ...` chains rewrite multiple times. Depth is
  bounded by the 128-char line (~42), frames ~176 B ->
  worst-case ~8 KiB stack, under the 16 KiB kernel
  stack, so safe.
- Crypto code is not constant-time (same class as the
  rest of the stack; tag comparison and bignum paths
  included). Documented, not a release blocker for this
  threat model.

## Carried weaknesses (pre-existing, unchanged by v1.1.3)

- TCP ISN predictable.
- FS bitmap/directory commit not atomic
  (hardware-fault-only window).
- Shell `dhcp`/`dnsset` and the Network-window DNS Set
  have no uid gate (pre-existing since v0.9.0; repo/TLS
  verification does not depend on DNS alone).
- Early-boot CSPRNG strength is limited until the first
  input event (documented in docs/WEB_SSL.md).
- No constant-time guarantees in crypto code (see above).

## Verdict

One exploitable finding (F1) was found by this read and
is FIXED and retested before shipping (host test +
QEMU wrapped-cert test + full TLS suites on the release
ISO). No other exploitable findings were found in the
changed surfaces. The carried weaknesses above remain
known and documented.
