# nxtsOS Vision

nxtsOS is an original, ultra-lightweight, customisable desktop OS:

- Familiar to Windows users, without copying Windows.
- Beautiful by default, but cheap to run: a basic graphical desktop is the
  target for 128 MB RAM, a comfortable one for 256 MB (see MEMORY_BUDGET.md).
- Honest about scope: a feature counts only when it runs in the VM and is
  recorded in a test report. Decorative buttons do not count.

Design principles, in order:

1. Bootable at every milestone. Never trade a working boot for a roadmap claim.
2. Small and explicit. Prefer a few hundred lines of readable kernel code
   over clever, opaque code.
3. Measure, don't assert. RAM, boot outcome, and test results are recorded
   from the actual QEMU run, with the exact command line used.
4. Security later is security never: privilege boundaries and input
   validation are part of the kernel phases, not an afterthought, even though
   v0.1.0 (a ring-0 diagnostic kernel) does not have them yet.
