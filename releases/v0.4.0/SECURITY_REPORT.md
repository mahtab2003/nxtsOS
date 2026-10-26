# nxtsOS v0.4.0 — Adversarial Security Report

Method: `docs/SECURITY_TESTING.md`. Attacker view for this release: a
malicious ELF, a malicious local user, a stolen session, and a
tampered users file are all untrusted input.

## Cases run (all in QEMU, QEMU 8.2.2)

### Boot A — Malformed ELFs + syscall abuse (PASS)

Disk seeded with 8 malformed ELFs, the evil ELF, the good ELF, and
root+user accounts. Logged in as root, ran each bad file, then the
evil ELF, then the good ELF, in one boot:

| Case | Result |
|---|---|
| ELF magic changed to `XXXX` | Refused: "run: cannot run badmagic.elf" |
| ELF truncated to 10 bytes | Refused |
| Program-header count = 1000 | Refused |
| Segment offset = 0xFFFFFF00 (beyond file) | Refused |
| Segment address = 0x00100000 (kernel region) | Refused |
| Segment address = stack page (0x0BFFF000) | Refused |
| Entry = 0x08049000 (outside loaded segment) | Refused |
| Segment memsz = 0x10000000 | Refused |
| Evil ELF: print with kernel pointer | Rejected (-1), program reported it |
| Evil ELF: read_file with kernel filename pointer | Rejected |
| Evil ELF: read_file with kernel buffer pointer | Rejected |
| Evil ELF: read_file with null buffer pointer | Rejected |
| Evil ELF: write_file with kernel data pointer | Rejected |
| Good ELF after all of the above | Ran normally, shell survived |

In every case: exactly 1 boot, no panic, no exception, no page fault,
shell prompt returned after each refusal.

### Boot B — Login brute force (PASS)

Three consecutive wrong passwords for user "user": the kernel printed
"Too many failed attempts. System halted.", no shell prompt appeared,
no reboot loop, no panic. (A fresh boot resets the counter — rate
limiting is per-boot, not persistent; see known limits.)

### Boot C — Malformed users.txt (PASS)

Users file with a first line containing no colons, followed by a valid
root line: the bad line was skipped with a warning, root login still
worked, shell worked, no panic.

## Findings

No exploitable findings in this release. All cases above were
rejected cleanly on the first run; no code fix was required after
testing. (The huge-total-sectors DoS from v0.3.0 remains fixed; its
bitmap-coverage check is unchanged.)

## Known limits (recorded honestly, not fixed by claiming otherwise)

- Password hash is FNV-1a (fast, no work factor): offline brute force
  of short passwords is possible for anyone with the disk image.
  See docs/SECURITY.md.
- Brute-force protection is per-boot (3 attempts, then halt); a
  reboot resets it. Persistent lockout / delay is a hardening item.
- Session lock timeout (10 minutes) is not QEMU-tested (see TEST_REPORT).
- No disk encryption: permissions protect against other logged-in
  users, not against raw disk access.
