# nxtsOS v1.1.2 — Security report

Adversarial third-party-style re-read of the changed verifier
(`net/tls.c` only: stop-at-anchor in `verify_chain`, oversize-key
handling in `parse_cert`). No exploitable findings.

## Change under review

Before v1.1.2, `verify_chain` walked the whole presented chain to
its terminal certificate and demanded the terminal satisfy the
mode's trust rule; `parse_cert` aborted the whole certificate on
any `bn_from_be` failure (which for RSA keys means only "modulus
over 2048 bits"). The live Vercel chain (leaf + WR1 intermediate +
4096-bit GTS Root R1) therefore failed at parse time in both TOFU
and anchored modes. v1.1.2 makes the validated path a PREFIX of
the presented chain: anchored mode stops at the first pinned
anchor; TOFU mode stops just before the first oversize-key
certificate. Everything inside the path is still fully verified.

## Cases checked — all hold

1. Anchor present, later certificate malicious: IRRELEVANT BY
   DESIGN. Path validation stops at the trust anchor (RFC 5280):
   once a chain certificate matches a pinned anchor, the path is
   complete and certificates after it are never read for trust.
   A malicious post-anchor certificate cannot influence the
   decision, because no code path consults it afterwards.
2. Attacker presents the anchor certificate itself with a forged
   leaf: STILL FAILS. The leaf-to-anchor link is inside the path:
   the leaf's signature is verified with the anchor's key, and
   the leaf's issuer must equal the anchor's subject. A forged
   leaf does not carry a signature that verifies under the real
   anchor key, so the handshake refuses exactly as before.
3. Anchor matching is exact, not prefix/substring: `tls_anchor_match`
   compares the full 256-byte modulus with `bn_cmp` and requires
   exponent 65537. `tlsanchors.txt` lines must be exactly 512 hex
   characters; malformed lines are skipped, never partially
   matched. No substring, prefix, or truncated-modulus match exists.
4. TOFU truncation grants nothing new: TOFU already accepted any
   chain whose tail was simply not sent by the server. Truncating
   at the first oversize certificate accepts exactly the chains
   that would be accepted with that tail withheld. A first-use
   MITM could already present any chain it likes, so the rule
   adds no attacker capability. (Precision note: this argument
   holds because the truncation point is the FIRST oversize
   certificate — every link before it is still fully verified,
   including signatures, dates, CA flags, and hostname.)
5. Oversize keys inside the validated path always refuse: the
   modulus is zeroed on parse failure, never truncated, so
   `verify_signature` fails (`bn_bitlen` 0 gives k=0 < 62).
   A belt-and-braces refusal also fires if any oversize
   certificate sits inside the path. A chain whose LEAF key is
   oversize is refused outright (empty path).
6. Anchor expiry still enforced: dates are checked for every
   certificate up to and INCLUDING the anchor. An expired anchor
   refuses, same as before.
7. Path-length bounds safe: anchored paths have length >= 2
   (anchor at index >= 1, leaf at 0); TOFU paths have length
   >= 1 (empty path refused). No underflow in the rewritten loop.
8. Anchor file reads bounded: `tls_anchor_match` reads at most
   5 `tlsanchors.txt` entries per handshake into a static
   8192-byte buffer. No unbounded read, no stack buffer.
9. The earlier "lone oversize CA certificate accepted" concern
   does NOT materialize: a chain consisting of a leaf plus a
   single oversize CA certificate truncates to the leaf alone in
   TOFU mode, and the leaf alone is not a valid TOFU terminal
   (not self-signed with verifying self-signature, not CA:true),
   so it refuses. In anchored mode the same chain has no anchor
   and refuses.

## Carried pre-existing limitations (NOT introduced by this fix)

- No pathlen enforcement: the validated path leaf→WR1 is
  consistent with WR1's pathlen:0 (WR1 issues the leaf, and the
  path stops at WR1), so this gap does not affect the Vercel case.
- xorshift RNG is not cryptographic; TCP ISN predictable.
- FS bitmap/dir commit not atomic (hardware-fault-only).
- Shell `dhcp`/`dnsset` and the Network-window DNS Set have no
  uid gate (pre-existing since v0.9.0; repo/TLS verification does
  not depend on DNS alone).
- 4096-bit RSA verification still NOT IMPLEMENTED for links that
  must actually be verified.
- No TLS 1.3, ECDSA certificates, or general CA store.

## Verification of the security-relevant tests

- New `tls_anchor_stop` (8/8 on the release ISO): repo-good with
  the exact live 3-cert chain succeeds; repo-badanchor,
  repo-badsig, repo-wronghost, repo-expired refuse; live-anchored
  and live-tofu with the exact live DERs pass certificate
  verification (guest ClientKeyExchange observed); live-wronghost
  refuses with no ClientKeyExchange.
- Existing TLS suites re-run on the release ISO: `tls`,
  `tls_chain` (5/5), `tls_anchor` (3/3), `tls_ske`, `tls_ecdhe`,
  `tls_peer`, `tls_hostmatch`, `tls_alpn`, `repo_https`,
  `repo_httpsa` — all PASS (see TEST_REPORT.md).
