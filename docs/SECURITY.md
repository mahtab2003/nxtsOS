# Security

Current state (v0.7.0): paging + ring-3 user mode + syscall gate are
implemented, filesystem permissions are enforced, and login/sessions
exist. See below for what is actually enforced and what is not — the
limits are part of the design, not footnotes.

## Implemented (v0.7.0)

- **Privilege boundary:** user programs run in ring 3, kernel in ring 0.
  Every syscall argument is validated in kernel mode before use:
  pointers must lie in the process's mapped code pages or its stack
  page, strings must be NUL-terminated within bounds, buffer lengths
  are capped. A kernel pointer, null pointer, or out-of-range buffer
  returns -1, never a kernel fault (tested with a malicious ELF).
- **ELF loader validation:** magic, 32-bit/LE/version, ET_EXEC, i386,
  program-header bounds against file size, segment offset/filesz
  bounds, segment address in user space only (never kernel region,
  never the stack page), entry inside a loaded segment, per-segment
  and total size caps. Any failure rejects the whole program.
- **Users and permissions:** UID per process, file owner/mode enforced
  on every VFS read/write/delete (owner/other bits; root UID 0
  bypasses). `ls` shows only files the current user can read.
  System files `users.txt` and `audit.log` are root-only: non-root
  users cannot create, write, delete, or (for the audit log) read them.
- **Login and sessions:** text login against `users.txt` on disk
  (username, UID, salt, password hash — never plaintext). 3 failed
  attempts halt the system. Logout clears the session and returns to
  the login prompt. Idle lock after 120 minutes of no input by default
  (v0.7.1; `idle` changes it per session); password
  re-entry for the same user, failure logs out.
- **Audit log:** `audit.log` on disk records login-ok, login-fail,
  login-locked, logout, and unlock events with timer ticks. An
  unlock of a real account audits "unlock <name>"; an unlock of
  an unknown name audits nothing (the no-such-user refusal
  returns before audit()), proven by read-back in
  `tests/qemu_test_audit_log.py` — root `cat audit.log` shows
  the real unlock and no entry for the refused name, and a
  non-root `cat audit.log` is refused. The desktop Settings
  Unlock path audits through the same primitive, proven by
  read-back in `tests/qemu_test_desktop_unlock_audit.py` —
  root `cat audit.log` after a mode-28 unlock shows exactly
  one unlock entry, so the empty-field refusal in the same
  script audited nothing. The non-root desktop refusal's
  absence is proven the same way in
  `tests/qemu_test_desktop_unlock_nonroot_audit.py` — a
  non-root mode-28 run followed by root `cat audit.log`
  shows zero unlock entries, so neither refusal in that
  script audits anything. It is root-only
  and append-only in the kernel API (capped at 4096 bytes; when full
  it stops logging with a console warning instead of truncating —
  proven by read-back in `tests/qemu_test_audit_cap.py`, which
  pre-seeds the log because filling it with real events would
  take ~200 entries: a 4080-byte seed refuses the login entry,
  warns, and hashes byte-identical to the seed, while a
  4000-byte seed gains exactly one login-ok entry). The
  read-back there uses `sha256` because it proves byte identity,
  not because `cat` cannot show the log: `cat` now walks any
  file in 1023-byte windows (`fs_read_range_as`, proven by
  `tests/qemu_test_cat_large.py` on a 2500-byte file and on a
  pre-seeded audit log), so a near-full log displays in full
  even as root. The old 1023-byte display limit is closed.
- **Stronger password hash (v0.4.1, breaking change):** salted
  FNV-1a iterated 10000 times (kernel and tools/mkuser.py match
  exactly), with a random salt per user when mkuser.py is run without
  an explicit salt, and empty passwords never match. Each guess is
  ~10000x more expensive than v0.4.0's single round. v0.4.0 users.txt
  files must be regenerated; old hashes will not log in.
- **Runtime password change (post-v1.0.0):** shell `passwd [user]`
  changes a password without rebuilding users.txt offline. Root
  changes any user without the current password; a non-root user
  changes only their own password and must first pass the current-
  password check. Prompts are echo-off, the new password must be
  retyped identically, and empty new passwords are refused. The
  change rewrites users.txt root-owned 0600 from the loaded table
  with only that user's salt+hash replaced (other users' lines are
  re-emitted unchanged in content), reloads the table, and verifies
  the new password checks before reporting success; a successful
  change is audited as `passwd <user>`. Limits, stated not hidden:
  the fresh salt comes from the 100 Hz tick counter plus a change
  counter (the kernel has no hardware RNG) — a salt is public data
  and only needs to be distinct, which that gives; a wrong
  current-password answer at the `passwd` prompt is NOT a login
  attempt, so it neither counts toward the 3-failure lockout nor
  audits; and changing a password does NOT clear a lockout —
  root still runs `unlock <user>`. Proven by tests/qemu_test_passwd.py
  (root change, self change, other-user refusal, wrong-current
  refusal, mismatch refusal, empty refusal, unknown-user refusal,
  users.txt still root-owned 0600, audit entry present).
- **Background processes (v0.4.1):** `runbg <file>` starts an ELF as
  a background job (up to 4, pid 10+), `jobs` lists them, `kill <pid>`
  kills only the owner's jobs (root can kill any), and logout kills
  the session's jobs. Jobs are resumed from the shell's idle loop,
  so the prompt stays responsive (yield and 100 ms timer preemption
  both return to the shell).
- **Persistent brute-force lockout (v0.4.1):** failed logins are
  counted in root-only `fails.txt` on disk. At 3 cumulative failures
  the account is locked even with the right password, and a reboot
  does not reset it. Root unlocks with `unlock <user>` (which also
  clears the count); a successful login clears it too. The per-boot
  3-attempt halt remains as well.
- **Graphics/input (v0.7.0):** see `docs/GRAPHICS.md`. Framebuffer
  drawing is clipped to the screen and to window bounds (s32
  coordinates, never unsigned underflow), windows are clamped not
  rejected for negative/huge coordinates, window count capped at 8,
  mouse packets with overflow bits ignored for movement, buttons
  only trigger on release inside the button, user programs cannot
  access the framebuffer directly (supervisor pages; GUI syscalls
  were added in Phase 8 — SYS_GUI_OPEN/RECT/TEXT/EVENT/CLOSE, with
  windows scoped to the calling process).
- **Disk encryption (v0.6.0):** see `docs/ENCRYPTION.md`. AES-256-CTR
  sector encryption, boot passphrase with key-check, 3-attempt halt,
  10000-round SHA-256 key derivation with per-disk salt. Unencrypted
  disks boot unchanged. Raw-disk string check, superblock tamper,
  header tamper, and package tamper on an encrypted disk all PASS.
- **Packages (v0.5.0):** see `docs/PACKAGES.md`. Install verifies
  manifest, blob layout, every file SHA-256, dependencies (including
  version operators), and target-file ownership before writing
  anything; removal is refused if another package depends on it
  (unless forced, with a warning); load-time SHA-256 verification
  refuses a tampered installed file. Install/remove are root-only.
  Registry `packages.txt` is root-only (mode 0600, system file).
- **Session lock (v0.4.1):** idle timeout raised from 10 to 30
  minutes, then to a 120-minute default in v0.7.1, the activity stamp
  is refreshed after a command finishes
  (so a long `run` does not cause an immediate lock on return), and
  `lock` locks the session on demand. The lock/unlock code path is
  QEMU-tested via `lock`, and the timeout trigger itself is now
  waited out in tests via `idle 1` (see limits).

## Honest limits (v0.4.1, not hidden)

- **Disk encryption limits (v0.6.0).** No passphrase change, no
  recovery key, no authenticated encryption (CTR gives
  confidentiality, not integrity — corruption is caught by
  superblock/file/package checks, not by a MAC), and offline brute
  force is limited only by the 10000-round work factor, so a weak
  passphrase is guessable. See `docs/ENCRYPTION.md`.
- **Package signing (implemented, Phase 11, v1.0.0).** This bullet
  used to say signing was NOT implemented; that was true in v0.5.0
  and is false now, and it contradicted `docs/PACKAGES.md`, which
  already records the gap as closed. Packages are NXPKG002 with an
  RSA-2048 signature over the manifest, verified against the
  compiled-in vendor key or a root-owned `pubkeys.txt` keyring;
  unsigned legacy (NXPKG001) packages, wrong-key packages, and
  tampered packages are all refused. See `docs/PACKAGES.md`
  ("Package signatures") and `tests/qemu_test_pkgsig.py`. What
  signing does NOT add: a revocation list — removing a key means
  editing `pubkeys.txt` (vendor key rotation means rebuilding and
  re-signing) — and a signature proves who signed, not that the
  author is safe, so root must still only install packages from
  trusted sources.
- **Upgrade atomicity limit.** Normal installs roll back on a failed
  write; an upgrade that fails mid-write (disk error only, after
  pre-checks) could leave mixed files while the registry still names
  the old version. See `docs/PACKAGES.md`.
- **Password hash is stronger but still not a production KDF.** The
  10000-iteration hash has a work factor but no memory hardness, so a
  well-resourced attacker with the disk can still brute-force weak
  passwords, just much more slowly. A memory-hard KDF
  (bcrypt/scrypt/Argon2) was a Phase 11 hardening item, but Phase 11
  shipped (v1.0.0) with signing, adversarial review, and update
  verification and without a memory-hard KDF, so it remains
  outstanding, not a Phase 11 item still to come. Do not deploy
  where the disk itself is untrusted and passwords are the
  only barrier.
- **Disk encryption exists since v0.6.0; this bullet used to say
  there was none.** See "Disk encryption (v0.6.0)" above and
  `docs/ENCRYPTION.md`. The permission-only statement below now
  applies to *unencrypted* disks only: on an unencrypted disk, file
  permissions protect against other *logged-in users*, not against
  someone with the raw disk image.
- **No users file = setup mode.** If no `users.txt` exists, the system
  boots as root with a warning, so a fresh disk can be configured.
  That is a deliberate setup mode, not a backdoor: seed `users.txt`
  before any multi-user use.
- **Session lock timeout trigger is QEMU-tested (desktop +
  shell-prompt paths, post-v1.0.0).** `tests/qemu_test_idle_lock.py` sets `idle 1`,
  enters the desktop, and waits out the 60-second timeout to the
  lock screen, then unlocks with the session password, and
  `tests/qemu_test_shell_idle_lock.py` does the same wait at the
  shell prompt itself — so the trigger code path (the idle-minutes
  value times 6000 ticks) is proven for both loops, not just the
  lock/unlock path via the `lock` command. Waiting out the
  120-minute default itself is still not feasible; the 1-minute
  waits prove the trigger path, not the default value.
- **Background jobs have no terminal job control yet.** A background
  program's output interleaves with the shell prompt, and there is
  still no kill/inspect syscall for user programs (kill is a shell
  command for background jobs only, checked by UID). When a syscall
  is added, it must check UID (owner or root).

## Planned, in order — and what already shipped

The list below was written at v0.4.1; items 1, 2, and 4 have since
shipped, and item 3 has shipped except for the KDF, so leaving them
as "planned" contradicted the rest of the docs. They are kept here,
marked, rather than deleted, so the history stays readable.

1. Phase 6: package verification (hashes on install and load, signing
   design) — DONE in v0.5.0 (hashes) and v1.0.0 (signing, above).
2. Phase 9: TLS with certificate verification — DONE in v0.9.0
   (TLS 1.2 client, `docs/NETWORKING.md`); no "accept all certs"
   mode is shipped as a default, and diagnostics must not bypass
   verification.
3. Phase 11: package signing, full adversarial review, and update
   verification before install — DONE in v1.0.0 (see
   `docs/PACKAGES.md`); memory-hard password KDF (and key
   derivation) — STILL OUTSTANDING, see the password-hash bullet
   in Honest limits above.
4. Disk encryption — DONE in v0.6.0 (AES-256-CTR sector encryption
   plus boot-time key management, `docs/ENCRYPTION.md`). A simple XOR
   "encryption" was deliberately NOT added — it would give false
   security.

Rules that apply from day one:

- No secrets, passwords, keys, or tokens in source, logs, or archives.
  (Test passwords in test scripts are test-only and are not real
  credentials; the shipped disk images contain no real user passwords.)
- No network code that trusts remote input without bounds checks.
- Every unhandled exception panics visibly (message + halt) rather than
  continuing in a corrupt state.
