# nxtsOS v1.1.5 — Security Report (adversarial third-party-style read)

Release ISO: `build/nxtsOS.iso`, 5,517,312 B,
SHA-256 `b4d42ad595ae84908ea302d438fba603d783e63787869418aeb0b59124767de3`
(kernel `build/nxtsOS.bin` 394,132 B). Scope: full diff vs
v1.1.4 (the core CLI completion families, plus the
tampered-CV test and the WEB_SSL note). Method: manual
adversarial review of the new code, read in full —
`net/fw.c` (341 lines) + `net/fw.h`, `kernel/acpi.c`
(229 lines), `kernel/editor.c` (618 lines),
`kernel/users.c` (338 lines), `kernel/groups.c`
(276 lines), `kernel/hwinfo.c` (176 lines), plus the
shell handlers for shutdown, useradd, userdel,
groupadd/groupdel/groupmod, passwd, and fw — plus the
adversarial coverage of the core suites on the release
ISO (Phase E 6/6). No fuzzer was run; the checks below
are the reviewer's reasoning plus the tests named.

## Finding: none exploitable in the new surfaces

- Firewall (`net/fw.c`, `net/fw.h`, FW_MAX_RULES 16).
  Parsers use overflow-checked decimal parsing and
  bounded port-range parsing; `fw_split` returns -1 on
  overflow (this fixed a real bug found by the
  malformed-file test during the core run: the old
  splitter capped at 7 words instead of rejecting
  8-word lines). The load path skips lines >= 256
  bytes; first-match semantics; drop counting counts
  packets, never contents; persistence is root-owned
  0600 via `fs_write_as`, lazily loaded, with
  malformed lines skipped. The shell handler root-
  gates every mutation; status/list/stat stay
  world-readable. Worst-case `fw.txt` save is ~1150
  bytes against a 2048-byte buffer. Suite proof on
  the release ISO (core_fw 71 checks): bad direction /
  port / inverted range / short rule refusals,
  del-out-of-range refusal, denied-traffic drop proofs
  in both directions, range-boundary proofs,
  persistence across reboot, non-root refusals.
- ACPI (`kernel/acpi.c`). The RSDP→RSDT→FADT→DSDT
  chain is walked with every checksum and length
  check failing closed; the `_S5_` package parse is
  bounds-checked at every element step; SLP_TYP is
  3-bit validated; if firmware ignores the poweroff
  write the machine halts forever — never a fake
  poweroff. PM1a_CNT_BLK is read at FADT offsets
  64/68 (the offset-56 bug from the core run is
  fixed). Absent or malformed tables yield "ACPI
  poweroff unavailable" + halt. Suite proof
  (core_power 21 checks): root-only gate, confirm
  unless `--force`, real QEMU process exit on
  poweroff (the strongest possible proof),
  malformed-table fail-closed behaviour.
- Editor (`kernel/editor.c`). File-scope 32 KiB + 1
  buffer (never a large stack array — the kernel
  stack is 16 KiB); insert/delete/paste bounds;
  cut capped at 1024 bytes; search bounded; save
  preserves mode and ownership with owner-change
  reporting; load normalisation is documented.
  `console_set_cursor` clamps and `console_put_at`
  drops out-of-bounds writes, so long-line cursor
  rendering cannot escape the screen. Suite proof
  (core_edit 59/59 hardened): oversized-file refusal
  at exactly 32768 bytes ("edit: file too large (max
  32768 bytes)"), unsaved-change prompt paths,
  save-as, search wrap, cut/paste, help.
- Users/groups (`kernel/users.c`, `kernel/groups.c`).
  Malformed lines are skipped with bounds; uid/gid
  caps 100000; duplicate and cap refusals; rewrite +
  reload + verify discipline; overflow flags refuse
  truncated writes rather than writing them; group
  membership validation includes root as an implicit
  identity; `groups_names_for_user` returns -1 on cap
  overflow rather than truncating. Password handling:
  echo-off prompts, buffers cleared on every return,
  non-root own-only + current-password check that
  neither counts toward lockout nor audits, root
  any-user, `userdel` refuses root and the session
  user, `fails.txt` record dropped on delete.
  `fs chown` is root-enforced in the fs layer too
  (`fs_chown_as`), not only in the shell handler, so
  a future caller cannot bypass the gate; `fs stat`
  discloses metadata only to root, the owner, or a
  reader. Suite proof (core_users 82 checks):
  duplicate / bad-name / unknown-user / unknown-
  group refusals, non-root refusals for every
  privileged op, root/session-user delete refusals,
  chown unknown-user / missing-file refusals.
- Hardware/resources (`kernel/hwinfo.c`). CPUID
  EFLAGS ID-bit test restores flags; brand/vendor
  buffer sizes respected; PCI scan is bus-0 only;
  RTC update-in-progress wait is bounded at 100000
  with binary/BCD modes, 12-hour conversion, and
  range validation rejecting invalid BCD digits.
  Suite proof (core_hw 34 checks).
- Tampered-CertificateVerify (carried test, now in
  the regression set): 6/6 on the release ISO — every
  tampered server CertificateVerify (PSS flip, PSS
  wrong transcript, PSS wrong key, PSS wrong alg,
  ECDSA flip, ECDSA wrong transcript) is refused
  exactly at TLS 1.3 stage 3, with no bytes line and
  no panic. The TLS 1.2 and legacy paths have no CV
  verification point by construction (the guest
  offers no client certificate), so this is a
  TLS-1.3-only test, not an omission.

## Observations (NOT findings — safe direction or documented limits)

- FADT length has no upper bound in the ACPI
  checksum loop (RSDT capped at 64 KiB, DSDT capped
  at 1 MiB). A firmware-controlled hang risk only,
  not remotely exploitable under the threat model
  (firmware is trusted).
- `fw add` truncates its input at 127 chars
  (`addbuf[128]`), so a root-typed rule with trailing
  words beyond the cut could be accepted as its
  7-word prefix. Root-only footgun; every field is
  still validated. Not exploitable by a non-root
  attacker.
- `fw del` ignores trailing garbage after the first
  token and wraps u32 on huge numbers; the result is
  bounded by the <= 16 rule-count check, so it can
  only yield "no such rule" or a valid small index.
  Root-only.
- `fw` save failure leaves the in-memory rule live
  but unpersisted (documented behaviour; the rule is
  lost on reboot).
- Editor load breaks silently on a mid-file
  zero-length read (partial load, buffer preserved);
  RTC reads can straddle midnight (display artefact
  only); users/groups load prints one console line
  per malformed line (bounded by file size; the
  files are root-owned 0600).
- Password hash is FNV-1a×10000, not a production
  KDF (already documented; unchanged from v1.1.4).

## Carried weaknesses (unchanged from v1.1.4)

- Predictable TCP initial sequence numbers.
- Filesystem commit is not atomic.
- `dhcp`/`dnsset` lack a uid gate (pre-existing).
- Early-boot CSPRNG output before input is only as
  strong as RTC, boot timing, and MAC uniqueness.
- No constant-time cryptography; no fuzzer run.
- 4096-bit RSA verification for links that must
  actually be verified is NOT IMPLEMENTED (the
  chain-termination rule avoids needing it for the
  current anchored/TOFU paths).
