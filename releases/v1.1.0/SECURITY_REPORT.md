# nxtsOS v1.1.0 — Security report

Third-party-style adversarial testing, as required after every release.
Exploitable findings were fixed and retested before shipping;
unexploitable limits are recorded honestly below. All suites below
were re-run for v1.1.0; see TEST_REPORT.md for the per-suite verdicts
and for which ISO each suite ran on (candidate ISO for the full
sweep, release ISO for the compositor-fix re-verification).

## v1.1.0 — New surfaces reviewed

### `passwd` path: sound

Shell dispatch lets root change any password without the current
password (Unix-like) but restricts a non-root user to their own
password plus a current-password check (not a login attempt, so
probing cannot lock the account); passwords are read with echo off
and buffers cleared; `users_change_password` uses a fresh xorshift
salt (salt is not secret; weak in-kernel entropy is documented, not
hidden), a file-scope 1024-byte rewrite buffer with overflow refusal
(worst case 8 users x 65 bytes = 520 < 1024), rewrites users.txt
root-owned 0600, reloads the table, and verifies the new password
before reporting success. Verified by the passwd suite (including
the lockout-after-3-failures refusal path).

### Range reads, rename, chmod, copy: sound

`fs_read_range_as`: same lookup + permission check as `fs_read_as`
on every window; offset >= size returns 0 bytes; no wraparound
(want = size - offset with offset < size); sector bounds checked.
Shell `cat` walks in 1023-byte windows with a 1024-byte stack buffer
(kernel stack is 16 KiB; large arrays must be file-scope statics).
`fs_rename_as` / `fs_chmod_as` / `fs_copy_as`: rename refuses an
existing destination, requires write permission on source, and
refuses non-root creation/movement of system files; chmod is
root-or-owner only with mode <= 0777 refused-never-masked; copy
requires source readability, refuses an existing destination and a
non-root system-named destination, is owned by the caller with the
source mode kept (no new access granted), moves sector-by-sector
through the file-scope sector buffer, and unmarks claimed sectors
on mid-copy failure. `is_system_file()` now also covers
`tlsanchors.txt` (same planting rationale as `pubkeys.txt`).

### Desktop window actions: gated by session uid

Desktop window actions all use `shell_session_uid()` for fs/proc
operations and are root-gated where privileged: Files sysupdate /
install, Repo update / install / fetch / set, Packages remove /
rollback, Settings unlock; Monitor Kill uses `proc_bg_kill`, which
enforces owner-or-root. `users_change_password` is only reachable
via the gated shell `passwd` path.

### Repository HTTPS and anchored TLS: fail-closed

Repo URL parsing: bare host = HTTP, `http://` = HTTP, `https://` =
TOFU TLS (default port 443), `httpsa://` = anchored TLS;
exact-lowercase schemes only, other/uppercase scheme-shaped input
refused, never silently treated as HTTP; the TLS mode threads
through update/fetch/install; index signature + package hash +
package signature remain the content-trust root (documented design:
signatures, not TLS, carry authenticity).
TLS hostname matching allows only a single-label leading wildcard
(`*.example` matches `foo.example`, not `example` or
`a.b.example`), never for IP literals; anchored verification
requires the terminal certificate to be CA-flagged AND its
RSA-2048 key to equal a pinned anchor (compiled-in WR1 or a
well-formed 512-hex line of root-owned `tlsanchors.txt`; malformed
lines skipped with a console note; missing file is not an error);
TOFU mode keeps the self-signed-terminal rule. Anchor/leaf moduli
are public keys, so non-root readability is not a leak.
Verified by the TLS anchor / hostmatch / ALPN / ECDHE / peer
suites and the repo HTTPS / anchored-HTTPS suites.

### Fresh review findings — fixed and retested

1. Compositor present-path gap (REAL BUG, fixed): app paints in
   back-buffered mode never reached the visible framebuffer (see
   TEST_REPORT.md "The compositor fix"). This was a visibility
   defect, not a privilege or trust bypass: no check was skipped
   and no unprivileged path gained access. Fixed by presenting
   the painted rect after each GUI paint; verified by the
   calculator pixel checks on the release ISO plus the full
   GUI/security neighbour set.
2. Test-harness sendkey flakes (NOT kernel bugs, fixed in the
   tests): QEMU monitor sendkey occasionally delivers a key
   twice, garbling commands. The storage, chmod, package
   security, and desktop security tests now tolerate or retry
   garbled delivery; the GUI security expectation was updated
   for the deliberate MAX_WINDOWS 8 -> 16 change. In every
   case the kernel failed closed correctly (refused the
   garbled command, or held the security property while the
   test misread its own output). See TEST_REPORT.md.

### Carried v1.0.0 verdicts (re-run green on v1.1.0)

Package signatures (legacy / wrong-key / tampered refused;
vendor-signed manifest/blob attacks refused by their specific
checks; keyring acceptance root-gated); system updates (atomic
refusal, topological order, rollback, re-refusal); remote
repository (stale index refused, tampered index refused,
wrong-key package refused, 404/wrong-file refused on hash);
storage (8 corrupt-disk cases); Phase 5 (malformed ELFs,
syscall abuse, brute-force halt, malformed users.txt); v0.4.1
(background jobs, persistent lockout); encryption (no plaintext
on disk, superblock tamper, wrong passphrase, tampered ELF);
GUI (driver/WM edge cases); desktop security (non-root save
denied, lock screen, malformed GUI syscalls); network security
(400-frame flood, DNS loop, wrong-host / tampered / expired
certificates refused exactly 3 times).

## Known limits (unexploitable or out of scope, recorded honestly)

- Noted limit, NOT a blocker (pre-existing since v0.9.0,
  unchanged in v1.1.0): shell `dhcp` / `dnsset` and the Network
  window DNS Set have no uid gate (the code comment says so
  explicitly), so any logged-in local user can change the global
  DNS server. Repo/TLS verification does not depend on DNS alone
  (signatures + anchors).
- `fs_write_as` bitmap/directory commit is not atomic: if a disk
  write failed at exactly the directory-save step after the bitmap
  save, sectors could be orphaned. A guest program cannot trigger
  a targeted ATA write failure, so this is a robustness limit for
  real hardware faults, not an exploitable path. No journaling.
- No general CA trust store: TLS chains must end in a pinned
  anchor (`httpsa://`) or a self-signed terminal (TOFU
  `https://`). No revocation checking, no TLS 1.3 / session
  resumption / client certificates, no 4096-bit RSA verification.
- RNG is timer-seeded xorshift, not cryptographic. Do not use the
  TLS client for real secrets yet.
- TCP ISN is predictable; the stack is still single-connection
  with no fragmentation reassembly, no DNS CNAME following, no
  DHCP renewal/release.
- Package trust has no key-add command and no revocation list.
  Rollback is one generation only and restores files plus the
  registry, not side effects of package programs.
- Disk encryption has no passphrase change, no recovery key, no
  authenticated encryption, and a non-memory-hard KDF.
- Real mouse movement/clicking was never delivered in QEMU
  (scripted injection only); VirtualBox and real hardware were
  never tested for any release.
