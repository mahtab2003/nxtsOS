# nxtsOS v0.4.0 — Release Manifest (Phase 5)

- Version: 0.4.0 (Phase 5 — Loader, security and sessions)
- Kernel binary: `build/nxtsOS.bin` (31,956 bytes)
- Bootable image: `build/nxtsOS.iso` (5,154,816 bytes, El Torito via grub-mkrescue)
- Build command: `./scripts/build.sh`
- Multiboot check: `grub-file --is-x86-multiboot build/nxtsOS.bin` → OK
- Git tag: `v0.4.0` (local repository only)
- Source archive: `archives/code/nxtsOS-v0.4.0-source.tar.gz`
- Distribution archive: `archives/dist/nxtsOS-v0.4.0-dist.zip`
- Checksums: `releases/v0.4.0/SHA256SUMS`

## Implemented (v0.4.0)

Everything in v0.3.1, plus:

- **ELF loader** (`kernel/elf.c`): loads ET_EXEC i386 ELF32 programs
  from disk into a fresh ring-3 address space, with full validation
  (magic, class, machine, program-header bounds, segment bounds,
  user-space-only addresses, entry inside a loaded segment, size caps).
  Shell command `run <file>` runs a program to completion as the
  current session's UID, then frees its address space.
- **Users and permissions** (`kernel/users.c`, VFS `_as` API):
  UID per process, file owner/mode enforced on every read/write/delete,
  `ls` shows only readable files, system files `users.txt`/`audit.log`
  are root-only. Host tool `tools/mkuser.py` generates `users.txt`;
  `tools/mkdisk.py` now accepts `NAME:PATH[:MODE[:UID]]`.
- **Login and sessions** (shell): text login against `users.txt`
  (password hash, never plaintext), 3 failed attempts halt the system,
  `whoami`, `logout` (clears session, returns to login), audit log
  (`audit.log`, root-only, append-only, capped at 4096 bytes), idle
  lock after 10 minutes. If no `users.txt` exists, the system boots as
  root in setup mode with a warning (documented, not a backdoor).
- **Filesystem syscalls for user programs:** `getuid`, `read_file`,
  `write_file`, with the same user-pointer validation as `print`
  (mapped code/stack range, NUL-terminated names, capped lengths).
  Test programs `userland/hello.c` (real ELF, loaded from disk) and
  `userland/evil.c` (syscall abuse attempts) are built by `build.sh`.

## NOT implemented (explicit)

Package management, graphics, desktop, networking, background
processes (programs run via `run` execute to completion; logout
therefore has no background processes to kill — recorded as a future
requirement), a production password KDF (see SECURITY.md), disk
encryption. See `docs/ROADMAP.md`.

## Remote publishing

NOT DONE. Muse GitHub App repository selection for mahtab2003/nxtsOS
is still pending; no push has been made.
