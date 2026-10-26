# Security

Current state (v0.4.1): paging + ring-3 user mode + syscall gate are
implemented, filesystem permissions are enforced, and login/sessions
exist. See below for what is actually enforced and what is not — the
limits are part of the design, not footnotes.

## Implemented (v0.4.1)

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
  the login prompt. Idle lock after 30 minutes of no input (password
  re-entry for the same user; failure logs out).
- **Audit log:** `audit.log` on disk records login-ok, login-fail,
  login-locked, and logout events with timer ticks. It is root-only
  and append-only in the kernel API (capped at 4096 bytes; when full
  it stops logging with a console warning instead of truncating).
- **Stronger password hash (v0.4.1, breaking change):** salted
  FNV-1a iterated 10000 times (kernel and tools/mkuser.py match
  exactly), with a random salt per user when mkuser.py is run without
  an explicit salt, and empty passwords never match. Each guess is
  ~10000x more expensive than v0.4.0's single round. v0.4.0 users.txt
  files must be regenerated; old hashes will not log in.
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
- **Session lock (v0.4.1):** idle timeout raised from 10 to 30
  minutes, the activity stamp is refreshed after a command finishes
  (so a long `run` does not cause an immediate lock on return), and
  `lock` locks the session on demand. The lock/unlock code path is
  QEMU-tested via `lock`; the 30-minute timeout trigger itself is
  still not waited out in a test (see limits).

## Honest limits (v0.4.1, not hidden)

- **Password hash is stronger but still not a production KDF.** The
  10000-iteration hash has a work factor but no memory hardness, so a
  well-resourced attacker with the disk can still brute-force weak
  passwords, just much more slowly. A memory-hard KDF
  (bcrypt/scrypt/Argon2) is a Phase 11 hardening item. Do not deploy
  v0.4.1 where the disk itself is untrusted and passwords are the
  only barrier.
- **No disk encryption.** File permissions protect against other
  *logged-in users*, not against someone with the raw disk image.
- **No users file = setup mode.** If no `users.txt` exists, the system
  boots as root with a warning, so a fresh disk can be configured.
  That is a deliberate setup mode, not a backdoor: seed `users.txt`
  before any multi-user use.
- **Session lock timeout trigger is NOT QEMU-tested.** Waiting
  30 minutes in a test is not feasible; the lock/unlock code path
  itself is QEMU-tested via the `lock` command, and a 30-second idle
  test proves the shell does not lock early. The rest of the session
  logic (login, logout, audit) is QEMU-tested.
- **Background jobs have no terminal job control yet.** A background
  program's output interleaves with the shell prompt, and there is
  still no kill/inspect syscall for user programs (kill is a shell
  command for background jobs only, checked by UID). When a syscall
  is added, it must check UID (owner or root).

## Planned, in order

1. Phase 6: package verification (hashes on install and load, signing
   design) — builds on the UID/permission model above.
2. Phase 9: TLS with certificate verification — no "accept all certs"
   mode shipped as a default; diagnostics must not bypass verification.
3. Phase 11: memory-hard password KDF, full adversarial review,
   update verification before install.
4. Disk encryption (not in v0.4.1): a real implementation needs
   AES sector encryption plus boot-time key management, which is a
   full phase, not a bugfix. A simple XOR "encryption" was deliberately
   NOT added — it would give false security. See the v0.4.1 release
   notes for the plan.

Rules that apply from day one:

- No secrets, passwords, keys, or tokens in source, logs, or archives.
  (Test passwords in test scripts are test-only and are not real
  credentials; the shipped disk images contain no real user passwords.)
- No network code that trusts remote input without bounds checks.
- Every unhandled exception panics visibly (message + halt) rather than
  continuing in a corrupt state.
