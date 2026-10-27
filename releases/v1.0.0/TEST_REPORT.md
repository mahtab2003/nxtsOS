# nxtsOS v1.0.0 — Test report

Release ISO: `build/nxtsOS.iso`, 5,316,608 bytes,
SHA-256 `b396192d5f2f463e9eddd5bc434cb8412df3b2e26a80518642d5197e58a586cc`.
Kernel binary at build time: 193,484 bytes.
Tested 2026-10-27 on QEMU 8.2.2 (serial + VNC suites).
Bochs 2.7 was NOT re-run for v1.0.0: the Bochs suites
(guitest + desktopautotest) last passed on v0.10.0, and
Phase 11 changed no graphics/desktop code path except a
version string literal — but that is not a Bochs pass,
so it is not claimed as one. The same guitest,
wmautotest, and desktopautotest code paths were verified
under QEMU on the release ISO (see GUI security and
classic desktop above).

## Final full sweep on the release ISO (all PASS)

Every suite below was run against the release ISO b396192d…
itself (not an earlier build). The two suites whose first
sweep output was truncated by a log pipe, and the two suites
whose rerun reused a mutated disk, were re-run on fresh
fixtures; those fresh runs are the verdicts recorded here.

- base (kernel boot, test programs, shell): PASS
- storage security (8 corrupt-disk cases, no panic/hang): PASS
- Phase 5 security (malformed ELFs, syscall abuse, brute-force
  halt, malformed users.txt): PASS
- v0.4.1 functional (background jobs, kill, lock, logout): PASS
- v0.4.1 security (persistent lockout across reboot): PASS
- package security (signature + manifest attacks, tamper boot): PASS
- keyring acceptance (pkgsig): PASS
- system update + rollback (topo order, atomic refusal,
  upgrade, rollback, re-refusal): PASS
- encryption security (no plaintext on disk, superblock tamper,
  wrong passphrase, tampered ELF): PASS
- GUI security (driver/WM edge cases, pixel signature intact:
  teal 215200 / blue 5798 / white 9671): PASS
- classic desktop (cliptest, cursortest, desktopautotest): PASS
- desktop10 (Dark theme, workspaces, snap, restore): PASS
- desktop apps (calc + term install, Console/Editor/Viewer): PASS
- desktop10sec (invalid settings ignored, evil.txt sanitised,
  oversize BMP refused): PASS
- desktop web (DHCP, 8192-byte truncation): PASS
- desktop nonic (clean no-device report): PASS
- desktop security (non-root save denied, lock screen,
  malformed GUI syscalls): PASS
- calculator (install, '7' glyph, exact colours): PASS
- network slirp (e1000, DHCP, ping, HTTP; slirp DNS is
  BONUS-only — sandbox UDP block, a proven environment limit,
  not a kernel defect): PASS
- network peer (DHCP, ping, DNS, HTTP): PASS
- TLS (OpenSSL server, certificate verification): PASS
- network security (400-frame flood, DNS loop, wrong-host /
  tampered / expired certificates refused exactly 3 times): PASS
- repository (3 boots: signed index, anti-rollback, stored
  index survival, tampered index, wrong-key package): 15/15 PASS

## Earlier Phase 11.2 sweep (ISO 3057db70…)

The same suites all passed on ISO 3057db70… before the last
two hardening fixes (repository version/port overflow refusals)
landed. The only source difference between 3057db70… and the
release ISO b396192d… is those two refusal checks, which the
repository and package suites above re-verified on the release
ISO. No suite regressed across that change.

## Not tested (honest limits)

- Real mouse movement/clicking in QEMU or with a real pointer
  in Bochs (scripted injection only); Android Bochs, VirtualBox,
  and real hardware were never tested.
- Phone frame rates were never measured.
- Full idle timeouts were never waited out.
- DNS-name (non-IP) HTTPS was not separately tested end to end.
- Calculator arithmetic beyond the '7'-press glyph was not
  separately verified.
- Larger ELFs (>64 KiB), disks (>16 MiB), and packages with
  content over 131072 bytes are unsupported by design.
