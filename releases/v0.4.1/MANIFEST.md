# nxtsOS v0.4.1 — Release Manifest (v0.4.0 limits fix)

- Version: 0.4.1 (Phase 5 + limits fix, NOT a new phase)
- Kernel binary: `build/nxtsOS.bin` (35,972 bytes)
- Bootable image: `build/nxtsOS.iso` (5,158,912 bytes, El Torito via grub-mkrescue)
- Build command: `./scripts/build.sh`
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Git tag: `v0.4.1` (local repository only)
- Source archive: `archives/code/nxtsOS-v0.4.1-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.4.1-dist.zip`
- Checksums: `releases/v0.4.1/SHA256SUMS`

## Implemented (v0.4.1, over v0.4.0)

- Stronger password hash: 10000-iteration salted FNV-1a, random salt
  per user in mkuser.py, empty passwords never match. BREAKING: old
  users.txt hashes will not log in; regenerate with new mkuser.py.
  Still not a memory-hard KDF (Phase 11).
- Background jobs: `runbg <file>`, `jobs`, `kill <pid>` (UID-checked),
  logout kills the session's jobs. Jobs resume from the shell idle
  loop; test program `userland/slow.c` (time-based, ~5 s).
- Persistent brute-force lockout: root-only `fails.txt` counts
  failed logins across reboots; at 3 the account is locked until
  root runs `unlock <user>`. Per-boot 3-attempt halt remains.
- Session lock: idle timeout 10 -> 30 minutes, activity stamp
  refreshed after a command finishes, `lock` command for manual lock.
  Lock/unlock path QEMU-tested via `lock`; 30-minute trigger itself
  is not waited out in a test (documented).
- Fast startup test: P2 busy-wait is now time-based (30 ticks per
  iteration, ~1.5 s total), preemption proof kept (P1 prints during
  P2's busy loop). Fixed two measured problems: 50M iterations took
  tens of seconds on a slow host; 5M finished under one quantum on
  a fast host and proved nothing.
- Kernel banner now says v0.4.1 (was hardcoded v0.4.0 in main.c).

## NOT implemented (explicit)

Disk encryption (needs a full AES + key-management phase; a fake XOR
was deliberately not added), package management, graphics, desktop,
networking. See `docs/ROADMAP.md` and `releases/v0.4.1/SECURITY_REPORT.md`.

## Remote publishing

NOT DONE. Muse GitHub App repository selection for mahtab2003/nxtsOS
is still pending; no push has been made.
