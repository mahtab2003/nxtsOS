# v0.5.0 security report (adversarial test, 2026-10-26)

- tests/security_test_pkg.py PASS, two boots:
  Boot A: hello installed, then badhash (manifest hash replaced with
  zeros), badsize (manifest size +1, layout no longer adds up),
  badpath (file "../evil.elf"), badabs (file "/etc/passwd"),
  selfdep (package depends on itself), cyc_a / cyc_b (mutual
  dependency), need99 (depends hello>=9.9, only 1.0 installed),
  huge (file over 64 KiB cap), huge2 (package over 128 KiB buffer
  cap) — all refused, with the specific refusal messages in the log.
  After all refusals: pkg list shows only hello 1.0, ls shows no
  evil/self/a/b/need/big files, run hello.elf still works, no
  panic, no reboot, shell survives.
  Boot B (tamper): hello installed, VM terminated, one byte flipped
  in hello.elf's data sector on disk (offset 1000, 00 -> ff), boot
  again: `run hello.elf` prints "cannot run hello.elf" (load-time
  SHA-256 mismatch), while `pkg list` still shows hello 1.0.
- No exploitable findings in the package code; no post-test kernel
  fix was required. Two test-development fixes, not kernel fixes:
  a shell redirection bug in a test command that truncated a
  dependency (`hello>=1.0` became `hello` in an unquoted shell
  command — the package was rebuilt with quoting), and a stray
  `=1.0` file created by that redirection, deleted from the tree.
- Known gaps, stated not hidden:
  - No package signing. Hashes authenticate nothing about the
    author; root must only install trusted packages.
  - Upgrade mid-write failure could leave mixed files with the old
    registry version (pre-checks make this a disk-error path only).
  - Background-job output still interleaves with the prompt (v0.4.1
    limit, unchanged).
