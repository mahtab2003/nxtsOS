# nxtsOS v1.1.3 — Test report

- Release ISO: `build/nxtsOS.iso`, 5,439,488 bytes,
  SHA-256 `37563b592395162aff9c1a9c45901e236e4ac914e6a265968272f26bf46a44ef`
- Kernel binary: `build/nxtsOS.bin`, 316,212 bytes (at build time)
- Date: 2026-10-29. Tested on QEMU 8.2.2 (serial + VNC suites).
  Bochs was NOT re-run for v1.1.3 (last Bochs pass: v0.10.0).
- Runner: `~/workspace/nxtsOS-regression-v1.1.3/run_regression.sh`
  (results in `results.txt` there; verdict per suite is the
  LATEST `SUITE <name> PASS/FAIL` line for that suite).
- Gate: **87/87 PASS** (Phase A 28/28, Phase B 48/48,
  Phase C 11/11). No suite is left failing.

## Phase A — 28/28 PASS

base, storage, storage_sec, phase5, phase5_sec, v041, v041_sec,
pkg, pkg_sec, pkgsig, sysupdate, enc, enc_sec, gui_sec, desktop,
desktop10, desktop_apps, desktop10sec, desktop_web,
desktop_nonic, desktop_sec, calc, net, net_peer, tls, net_sec,
repo, v071.

## Phase B — 48/48 PASS

anchor_stop, tls_chain, desktop_fallback, shell_echo, tls_ske,
storm, tls_anchor, tls_hostmatch, tls_alpn, tls_ecdhe, tls_peer,
repo_https, repo_httpsa, repo_avail, repo_bench, repo_fetch,
repo_set, repo_scroll, repo_desktop, repo_root, repo_sysinfo,
files_run, files_install, files_hash, files_chmod, files_sysupd,
packages_remove, packages_rollback, monitor_jobs, monitor_disk,
network_dns, network_ping, desktop_logout, desktop_reboot,
desktop_unlock_audit, desktop_unlock_nonroot_audit,
settings_unlock, unlock_nouser, idle_lock, shell_idle_lock,
audit_cap, audit_log, cat_large, passwd, cp, mv, chmod, web_save.

## Phase C — 11/11 PASS

castore (10/10), tls13 (14/14), tls13_tampered,
tls13_wrappedcert, shell_groups, newapps, scroll, webpanic,
webpanic_desktop, desktop_expose, desktop_noconsole.

## The desktop_fallback gate (0/5 → PASS on a hardened re-run)

The release run was held at 86/87 with `desktop_fallback`
failing 0/5. Root cause, proven from evidence, is a harness
race, not a kernel bug: the test waited only for the `fb30:`
prefix, terminated QEMU at once, then asserted the FULL line.
All five failures cut the line mid-print at varying points
(`bg=0x`, `bg=0x18305`, `bg=0x1`, `saved=(300,43`) with zero
EXCEPTION/PANIC/page fault in any run. A manual boot of the
same ISO and command with a 3 s grace instead of an immediate
kill prints the full line
`fb30: saved=(300,432) bg=0x183050 green=0 web=1` — exactly
the expected values. The prefix→full gap measures 30.8 ms; a
timer tick landing in that window suspends the print for a
100 ms quantum, during which the harness's 100 ms poll observes
prefix-only and kills QEMU.

Hardening (test-only change in
`tests/qemu_test_desktop_fallback.py`, host tests are not in
the kernel build, so the release ISO is unaffected): the wait
condition now requires the FULL fb30 line regex to match in
the serial log before QEMU is terminated. This is a STRICTER
check — it asserts exactly what the verdict regex already
demanded — and it still fails closed (if the full line never
arrives within the 60 s timeout, the test FAILS). Nothing else
about the test changed: same boot, same command, same
assertions, same expected values.

Hardened re-run on the release ISO (37563b59…): PASS in
11.4 s — `fb30: saved=(300,432) bg=0x183050 green=0 web=1`,
all four checks PASS, EXCEPTION/PANIC/page fault all absent.
Gate after the re-run: 87/87, zero FAIL. One hardened re-run
was the authorised attempt; it passed, so no further attempts
were needed or made.

## Other FAILs cleared with proof (all re-run green)

- `desktop_logout`: first boot's `pkg install calc.nxpkg`
  timed out (sendkey-flake class; the logout flow itself was
  fully green in the failing run) → re-run PASS.
- `cp`: stale test substrings (`beta.txt  14 bytes`, two
  spaces) vs the intentional Work D list-view format (name
  padded to 24 columns; row fields unchanged, proven by git
  diff v1.1.2→tree). Test-only fix declared: padding-tolerant
  regexes `beta\.txt +14 bytes` / `bin2\.dat +256 bytes`
  (spaces only, same assertion strength, matches both
  layouts) → re-run PASS. `mv` (bare filenames) and `chmod`
  (mode values) verified immune by grep.
- `shell_groups`: the command was typed as `help casstore add`
  (doubled 's'); the guest correctly refused it, and the
  test's retry fires only on "Unknown command", so no retry
  happened → re-run typed correctly, PASS with
  `castore add (net)` present.

## Incidents during the run

- VM replacement mid-Phase-B (after `repo_root` PASS):
  /usr/bin tools wiped and the runner killed, but
  `~/workspace` survived intact (ISO hash re-verified,
  results.txt intact, fixtures intact). Toolchain restored
  from the apt cache (QEMU 8.2.2, `ldd` clean; some
  packages unconfigured but harmless for QEMU runs).
  The runner resumed from results.txt with zero green
  suites lost.
- /tmp exhaustion (512 MB tmpfs) failed one scroll re-run
  attempt with exit 120 and empty output; after cleaning
  /tmp the clean re-run PASSED. The exact mechanism of
  exit 120 was not isolated; the green rerun on clean
  /tmp is the verified result. /tmp was 0% at ship time.

## Host-side evidence (not QEMU suites)

- `tests/host_pss.c`: RSA-PSS verify 20/20 on fixed code.
- `tests/host_der_tlv.c`: DER length parsing 11/11 on fixed
  code (3/11 fail on the vulnerable code). See
  `releases/v1.1.3/SECURITY_REPORT.md` for the full
  security pass, including the exploitable `der_tlv`
  wraparound found, fixed, and retested in this release.

## NOT TESTED (honest)

Live Vercel guest fetch from the kernel (peer-harness proof
only); user-side Virt-Manager retests (repo commands,
desktop fixes, Phase 2 TLS 1.3); Bochs re-run for v1.1.x
trees; real-pointer mouse movement/clicking (scripted
injection only); real hardware; tampered-CertificateVerify
negative (not yet built); legacy SSLv2/v3/TLS 1.1
(Phases 3/4, no run order yet).
