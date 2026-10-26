# Security

Current state (v0.4.0): paging + ring-3 user mode + syscall gate are
implemented, filesystem permissions are enforced, and login/sessions
exist. See below for what is actually enforced and what is not — the
limits are part of the design, not footnotes.

## Implemented (v0.4.0)

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
  the login prompt. Idle lock after 10 minutes of no input (password
  re-entry for the same user; failure logs out).
- **Audit log:** `audit.log` on disk records login-ok, login-fail,
  login-locked, and logout events with timer ticks. It is root-only
  and append-only in the kernel API (capped at 4096 bytes; when full
  it stops logging with a console warning instead of truncating).

## Honest limits (v0.4.0, not hidden)

- **Password hash is weak by modern standards.** It is FNV-1a over
  salt+password: it stops plaintext storage, but it has no work factor,
  so an attacker who can read the disk can brute-force short passwords
  offline. A production KDF (bcrypt/scrypt/Argon2) is a Phase 11
  hardening item. Do not deploy v0.4.0 where the disk itself is
  untrusted and passwords are the only barrier.
- **No disk encryption.** File permissions protect against other
  *logged-in users*, not against someone with the raw disk image.
- **No users file = setup mode.** If no `users.txt` exists, the system
  boots as root with a warning, so a fresh disk can be configured.
  That is a deliberate setup mode, not a backdoor: seed `users.txt`
  before any multi-user use.
- **No background processes yet.** Programs run via `run` execute to
  completion in the shell's context, so logout has no background
  processes to kill. When background processes land, logout must kill
  the session's processes — recorded as a requirement, not assumed.
- **Session lock timeout is NOT QEMU-tested.** Waiting 10 minutes in
  a test is not feasible; the tick comparison is simple and reviewed,
  and the lock path is documented as untested here and in the release
  notes. The rest of the session logic (login, logout, audit) is
  QEMU-tested.
- **No kill/inspect syscall exists yet,** so there is no kill-permission
  check to test. When one is added, it must check UID (owner or root).

## Planned, in order

1. Phase 6: package verification (hashes on install and load, signing
   design) — builds on the UID/permission model above.
2. Phase 9: TLS with certificate verification — no "accept all certs"
   mode shipped as a default; diagnostics must not bypass verification.
3. Phase 11: stronger password KDF, full adversarial review, update
   verification before install.

Rules that apply from day one:

- No secrets, passwords, keys, or tokens in source, logs, or archives.
  (Test passwords in test scripts are test-only and are not real
  credentials; the shipped disk images contain no real user passwords.)
- No network code that trusts remote input without bounds checks.
- Every unhandled exception panics visibly (message + halt) rather than
  continuing in a corrupt state.
