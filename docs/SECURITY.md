# Security

Current state (v0.1.0): the kernel runs entirely in ring 0 with no user
processes, so there is no privilege boundary to audit yet. Claiming
"process isolation" for v0.1.0 would be false, and is not claimed.

Planned, in order:

1. Phase 3: paging + ring 3 user mode + syscall gate; kernel validates
   every syscall argument (pointer ranges, lengths) before use.
2. Phase 6: filesystem permissions (owner/group/other bits on the VFS).
3. Phase 7: TLS with certificate verification — no "accept all certs" mode
   shipped as a default; diagnostics must not bypass verification silently.
4. Phase 9: package signatures / update verification before install.

Rules that apply from day one:

- No secrets, passwords, keys, or tokens in source, logs, or archives.
- No network code that trusts remote input without bounds checks.
- Every unhandled exception panics visibly (message + halt) rather than
  continuing in a corrupt state.
