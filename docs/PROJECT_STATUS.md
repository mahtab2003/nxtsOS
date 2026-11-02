# nxtsOS Project Status

- Current version: 1.1.6 — accumulation release (Linux-comparability
  + deep-core + all five core redesigns: VFS/directories, block
  layer, sockets + TCP server, SMP stabilised, redesign 5 paging/
  vruntime/capabilities). Git tag v1.1.6 (local only; no GitHub
  push). Release ISO 5,687,296 bytes, SHA-256
  2f53912c3985200d4ceaff4c5354c62dd87624bdabee4070868b8e285813871d.
  Full gate 120/120 suites PASS — see releases/v1.1.6/TEST_REPORT.md
  and SECURITY_REPORT.md. (Supersedes the 1.0.0 line above and the
  v1.1.5 release, which was the previous shipped version.)
- CORRECTION: this file used to say "Current version: 0.2.0 — Phase 3
  complete" and "Next: Phase 4 graphics/input". Phases 4–11 have all
  shipped since: persistent storage (Phase 4, v0.3.0), loader/security/
  sessions (Phase 5, v0.4.0), packages (Phase 6, v0.5.0), disk
  encryption (v0.6.0), networking (Phase 9, v0.9.0), modern desktop and
  applications (Phase 10, v0.10.0), hardening/update (Phase 11, v1.0.0).
  See `docs/ROADMAP.md` for the phase record and `VERSION` for the
  released version.
- Location: `~/workspace/nxtsOS` (workspace directory; local git repo,
  branch main, no remote configured).
- Next phase: post-v1.0.0 extension under the autonomous mission
  (2026-10-27 to 2026-11-03): a NEW MODERN, glitch-free desktop UI,
  more utility and essential apps, more repository packages — in focus
  order core system, CLI features/packages, security, desktop apps.
  No new release is cut until its full regression sweep, adversarial
  security test, archives, checksums, tag, and reports are done.
- Remote publishing: CORRECTION — this file used to say "NOT DONE — no
  GitHub/authorised git-host account was connected". Versions v0.1.0
  through v1.0.0 were pushed to the dev branch of mahtab2003/nxtsOS on
  2026-10-27, authorised by the user for that push. Post-v1.0.0 work is
  local only, and the standing rule is: NEVER push to GitHub or show a
  push approval UI unless the user explicitly says to push. Do not claim
  a push happened for post-v1.0.0 work.
- Honest scope: CORRECTION — this file used to say "v0.1.0 is a
  text-mode diagnostic kernel" and "Desktop, storage persistence, and
  networking are future phases". nxtsOS is now a whole OS: text shell
  plus a modern desktop (v0.10.0), persistent nxtsfs storage (v0.3.0),
  networking (e1000/DHCP/DNS/TCP/HTTP/TLS client, v0.9.0), signed
  packages (v1.0.0), disk encryption (v0.6.0), system update with
  rollback (v1.0.0). Still NOT implemented, stated not claimed away:
  graphical boot login, package revocation list, memory-hard KDF
  (Argon2/bcrypt), user-mode socket API, HTML rendering (the Web app
  is a text viewer).
