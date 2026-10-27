# nxtsOS Project Status

- Current version: 0.1.1 — Phase 2 complete and QEMU-verified.
  v0.1.0 is superseded: it reboot-looped in QEMU (GDT selector bug, fixed
  in v0.1.1). Do not distribute v0.1.0.
- Location: `~/workspace/nxtsOS` (workspace directory; no user drive was
  identifiable/accessible, so the project lives here — see prompt section 6).
- Next phase: Phase 3 — paging, scheduler, processes, syscalls, ring 3.
- Remote publishing: NOT DONE — no GitHub/authorised git-host account was
  connected in this session. Local git repo + tag exist; push steps are in
  `releases/v0.1.0/MANIFEST.md`. Do not claim a push happened.
- Honest scope: v0.1.0 is a text-mode diagnostic kernel with a shell.
  Desktop, storage persistence, and networking are future phases.
