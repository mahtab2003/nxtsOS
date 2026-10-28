# nxtsOS v1.1.2 — Release manifest

- Version: 1.1.2 (patch release over v1.1.1: TLS certificate-chain
  verification fix for the live package repository host)
- Date: 2026-10-28
- Kernel: original 32-bit x86 monolithic kernel, Multiboot 1 via GRUB.
  No Linux code, no distro, no fork, no re-theme.
- ISO: `nxtsOS.iso`, 5,390,336 bytes,
  SHA-256 `4291f1ccd27a13837562956df0b8337acfb3cc6355bf215c01bdaaea0bffcf06`
- Kernel binary: `build/nxtsOS.bin`, 266,656 bytes (at build time)
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
- Git: branch `main`, tag `v1.1.2` (local only; no GitHub push —
  the user did not authorise a push for this release).
  The exact commit hash is recorded in the delivery notes, not inside
  this manifest, because the manifest itself is part of the commit.
- Tested on: QEMU 8.2.2 (serial + VNC suites) — see
  TEST_REPORT.md. Bochs 2.7 was NOT re-run for v1.1.2
  (last Bochs pass: v0.10.0); see TEST_REPORT.md.

## What is fixed in v1.1.2 (over v1.1.1)

The user reported, on v1.1.1, that in the shell
`pkg repo https://nxtsos-repo.vercel.app/` answered
"Repository set to https://nxtsos-repo.vercel.app/" but the next
`pkg update` answered "pkg update: repository certificate refused"
— "still same" as the v1.1.0 report. The v1.1.1 TOFU fix did not
cover this path, and the original brief misdiagnosed it as the
anchored path: `kernel/pkg.c` `repo_parse_url` maps `https://` to
mode 1 (TOFU TLS client) and only `httpsa://` to mode 2 (anchored
TLS client). The user typed `https://`, so the reported refusal
was the TOFU path — but the anchored path would have refused the
same chain too, so the fix covers BOTH paths.

Root cause, verified from the live server (not taken on faith):
the live host's TLS 1.2 chain, captured 2026-10-28 via a
CONNECT-tunnel probe (probe script + DERs saved outside the repo
at `~/workspace/vercel-chain-2026-10-28/`), is THREE certificates:

1. leaf CN=`*.vercel.app`, RSA-2048, CA:FALSE, SAN `*.vercel.app`,
   issuer WR1, valid 2026-08-29 to 2026-11-27 — fine;
2. intermediate CN=WR1 (Google Trust Services), RSA-2048,
   CA:TRUE pathlen:0, issuer GTS Root R1 — its modulus is
   byte-identical to the pinned anchor in `net/tls_anchor.h`
   (256 bytes, exponent 65537) — this IS the anchor;
3. root CN=GTS Root R1, RSA-4096, CA:TRUE, issuer GlobalSign
   Root CA. Servers normally do not send the root; Vercel does.

The kernel refused in both paths, for the same underlying reason:
`net/tls.c` `parse_cert` calls `bn_from_be`, which returns -1 for
keys over 2048 bits (`net/bignum.c`, BN_LIMBS 64; oversize is its
ONLY failure mode), so the 4096-bit R1 failed to parse before
`verify_chain` ever ran, and the handshake failed with
"certificate refused". The anchored path would additionally have
refused because the terminal cert (R1) is not the pinned anchor.

The fix (`net/tls.c` only, +90/-16):

- `struct cert_info` gains `int key_oversize` (the modulus is
  zeroed by `bn_from_be` on failure, never truncated).
- `parse_cert`: a `bn_from_be` failure now sets `key_oversize = 1`
  and continues parsing the rest of the certificate (dates,
  issuer/subject, CA flag, signature bytes) instead of
  returning -1.
- `verify_chain` rewritten: the VALIDATED PATH is a prefix of the
  presented chain. Anchored mode: the path ends at the FIRST
  pinned anchor certificate (index >= 1, `ca_flag == 1`,
  `tls_anchor_match`); no anchor means refusal; certificates
  after the anchor are ignored (RFC 5280 path validation stops
  at the trust anchor). TOFU mode: the path ends just before the
  first `key_oversize` certificate (equivalent to the server
  having withheld that tail, which TOFU already accepts); a chain
  whose LEAF key is oversize is refused (empty path). Inside the
  path, every rule still holds: dates for every path certificate,
  leaf hostname match, every link's issuer == next subject + CA
  flag + signature verification; a belt-and-braces refusal fires
  if any oversize certificate sits inside the path. Terminal
  rules apply to the path terminal (anchored: CA + anchor match
  restated as an explicit gate; TOFU: self-signed with verifying
  self-signature, or CA:true — unchanged). The anchor's own
  signature is never verified (the anchor IS the trust root by
  pinning).
- Preserved: 4096-bit refusal for any link that must actually be
  verified (zeroed modulus makes `verify_signature` fail); only
  links beyond the anchor/truncation point are ignored by design.

Also in this release: `docs/NETWORKING.md` TLS section corrected
to the new rules (TOFU oversize-tail truncation + the Vercel case;
anchored "must CONTAIN a pinned anchor, validation stops there";
the v1.1.1 behaviour description corrected), and a new peer-harness
test `tests/qemu_test_tls_anchor_stop.py` (+ setup) proving the
fix end to end with the exact live chain (see TEST_REPORT.md).

No other kernel behaviour changed. No new build warnings
(still the 7 pre-existing warnings). Kernel stack discipline kept
(only small locals added; `cert_info` grew 4 bytes x 4 certs).

## What is NOT in v1.1.2

- Live Vercel guest fetch from the kernel is still NOT TESTED
  (sandbox blocks guest DNS over slirp UDP; peer-harness proof
  only — see TEST_REPORT.md). The user-side retest on real
  QEMU/KVM via Virt-Manager (`pkg repo
  https://nxtsos-repo.vercel.app/` + `pkg update`, and the
  `httpsa://` variant) remains the key live proof.
- 4096-bit RSA verification is still NOT IMPLEMENTED for links
  that must actually be verified.
- No TLS 1.3, ECDSA certificates, general CA store, HTML
  rendering, installer, UEFI, or user-mode socket API — those
  belong to the queued web/SSL work, which is a separate
  pending-clarification request and is NOT started here.
