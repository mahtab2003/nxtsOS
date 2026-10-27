# Security Testing — third-party tester method

Every release is attacked before it ships, as if the tester did not
write the code and does not trust it. This document is the method; each
release's `SECURITY_REPORT.md` is the evidence.

## Principles

- **Assume the input is hostile.** Disk images, ELF files, packages,
  network packets, user keystrokes, and syscall arguments are all
  attacker-controlled until proven otherwise. "The user would never do
  that" is not a defence.
- **A crash is a finding.** A panic, hang, reset loop, or memory
  corruption on a malformed input is a security bug, even if it "only"
  crashes the VM — it is a denial of service and, in kernel code, a
  possible stepping stone to worse.
- **Privilege is the prize.** The test that matters most is: can an
  unprivileged process, file, package, or packet gain kernel privilege,
  another user's data, or another process's control? Every new API and
  every new driver gets that question asked explicitly.
- **Fix, then retest, then ship.** A finding is closed only when the
  fixed build passes the exact test that found it, plus the full
  regression suite. A finding left open ships only if it is provably
  unexploitable in the current release — and then it is listed as a
  known limitation with the reason, not buried.

## Method, per release

1. **Threat model:** who is the attacker for this release's new surface
   (malicious disk? malicious program? malicious network peer? malicious
   local user?), and what would they gain?
2. **Surface inventory:** every new parser, driver, syscall, file format,
   and protocol handler added in this release, with its inputs and
   bounds.
3. **Case list:** for each surface — malformed/truncated/oversized
   inputs, boundary values (0, 1, max, max+1), overlapping ranges,
   missing NUL terminators, path traversal, integer overflow in
   size/count arithmetic, resource exhaustion (many files, windows,
   connections, processes), and privilege-escalation attempts.
4. **Execution:** run each case in QEMU against the release candidate
   (or, for host-side parsers, against the host tool that shares the
   format). Capture the serial log and the outcome: clean error,
   panic, hang, or corruption.
5. **Triage:** exploitable (privilege, corruption, hang on untrusted
   input) → must fix before release. Clean error → pass. Unexploitable
   limitation → record as known, with the reason.
6. **Retest:** after fixes, re-run the failing cases and the full
   regression suite. The security report records before/after for
   every finding.

## What is NOT security testing

- Running the happy path and calling it a security test.
- Testing only with well-formed inputs.
- Claiming a feature is secure because it has not been attacked yet.
- Hiding a finding because it is embarrassing or because fixing it
  would delay a feature. The delay is the point.
