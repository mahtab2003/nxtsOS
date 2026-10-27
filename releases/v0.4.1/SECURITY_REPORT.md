# v0.4.1 security report (adversarial test, 2026-10-26)

- tests/security_test_phase5.py PASS 3/3 boots (regression, unchanged
  from v0.4.0): 8 malformed ELFs refused, evil ELF syscall abuse
  rejected with no kernel fault, brute-force halt, malformed users
  line skipped without locking root out.
- tests/security_test_v041.py PASS (new, persistent lockout): boot 1,
  3 wrong passwords for user -> halt; boot 2, same disk, correct
  password for user -> "Account locked. Contact root to unlock.",
  root login, `unlock user`, logout, user login with correct password
  -> succeeds. A reboot no longer resets the brute-force counter.
- New protections and their limits:
  - Password hash: 10000-iteration salted FNV-1a, random salt per
    user, empty passwords never match. BREAKING vs v0.4.0: old
    users.txt hashes will not log in; regenerate with mkuser.py.
    Still not a memory-hard KDF (bcrypt/scrypt/Argon2 is Phase 11).
  - fails.txt is root-only (system file, mode 0600, owner root), so
    a non-root user cannot clear their own lockout via the shell.
  - kill checks UID (owner or root); logout kills the session's
    background jobs only.
  - Background job output interleaving with the prompt is a UX
    limit, not a privilege issue: jobs cannot read each other's
    memory (separate page directories, validated syscalls).
- NOT fixed in v0.4.1, deliberately: disk encryption. A real
  implementation needs AES sector encryption plus boot-time key
  management (passphrase, key storage, recovery), which is a full
  phase. A simple XOR sector "encryption" was NOT added, because it
  would give false security while being trivially reversible from
  the disk image. File permissions protect against other logged-in
  users, not against raw disk access — same limit as v0.4.0, stated
  here, not hidden.
- No exploitable findings in the v0.4.1 changes; no post-test code
  fix was required (the two test failures during development were
  test-script disk setup and a too-fast background job, fixed in the
  test programs, not in kernel security code).
