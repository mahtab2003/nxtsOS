# nxtsOS v1.1.4 — Test report

- Release ISO: `build/nxtsOS.iso`, 5,472,256 bytes,
  SHA-256 `a2a4dbae29bf545274217dd693a9a1cf45463bfef53103014e0ec3865432114e`
- Kernel binary: `build/nxtsOS.bin`, 349,008 bytes (at build time)
- Date: 2026-10-29. Tested on QEMU 8.2.2 (serial + VNC suites).
  Bochs was NOT re-run for v1.1.4 (last Bochs pass: v0.10.0).
- Runner: `~/workspace/nxtsOS-regression-v1.1.4/run_regression.sh`
  (results in `results.txt` there; verdict per suite is the
  LATEST `SUITE <name> PASS/FAIL` line for that suite —
  the file accumulates history, so stale FAIL lines from
  fixed test bugs remain visible above later PASS lines).
- Gate: **98/98 PASS** (Phase A 28/28, Phase B 48/48,
  Phase C 11/11, Phase D 11/11). No suite is left failing.

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

## Phase D — 11/11 PASS (new in this release)

legacy (19/19), http (23/23), user, host_http (43/43),
host_legacy_crypto (21 checks), host_der_tlv (11/11),
host_ec256, host_pss, host_http_sec (83/83),
source_check, http_sec (9/9).

## FAILs cleared with proof (all test/harness bugs, zero kernel bugs)

- `desktop_sec` (Phase A): QEMU sendkey-doubling flake —
  the serial log proves it: `ppkg install calc.nxpkg` →
  `Unknown command: ppkg`, then `pkg list` → `(no packages
  installed)`, so the install never ran and the later
  `calc.elf not found on disk` assertion follows directly
  (boots A and B fully passed). Clean re-run PASS.
- `shell_groups` (Phase C): the test hardcoded the
  expected `ver` string `nxtsOS v1.1.3`, but the kernel
  correctly reports v1.1.4 after the version bump; every
  other check in the suite passed. Test-only fix: the
  test now reads VERSION from the repo root (same
  assertion strength, future-proof). Clean re-run PASS.
- `scroll` (Phase C): the same stale `nxtsOS v1.1.3`
  literal (all scroll checks — PgUp history view, PgDn
  live view, W-row pixels — passed). Fixed identically
  to `shell_groups`. Clean re-run PASS. A sweep of
  `tests/` found no other hardcoded version assertions
  (remaining `1.1.3` mentions are comments only).
- `user` (Phase D): the prompt check searched for the
  first `nxts> ` in the log, which is the early boot
  notice ("The nxts> shell prompt will appear when they
  finish"), not the prompt — so it failed on every run
  even though `root@nxts> ` is present after the finish
  line (all process/preemption checks passed). Test-only
  fix: require `root@nxts> ` after
  "All user processes finished." (STRICTER, not weaker).
  Clean re-run PASS.
- `host_pss` (Phase D): two harness gaps, not a kernel
  bug. (1) Link error: web/SSL Phase 3 added
  `rsa_verify_sha1` to `net/rsaverify.c`, which calls
  `sha1_compute`, but the runner's build line did not
  link `kernel/sha1.c`. (2) The test reads
  `/tmp/pss-{mod,sig,hash}.bin`, which no script in the
  repo produced. Fixes: build line gains `kernel/sha1.c`
  (and the header comment now records both facts), and
  new `tests/gen_pss_vectors.py` generates a real
  RSA-2048 PSS/SHA-256 vector set (prehashed digest,
  32-byte salt) before the build. Standalone run:
  `rsa_verify_pss_sha256 -> 0 (PASS)`. Clean re-run PASS.
- `http_sec` chunkhuge (Phase D): QEMU sendkey-doubling
  flake — the serial log shows `hhttp a.test /chunkhuge`
  → `Unknown command: hhttp`, and the peer saw no
  request, so the wait for `http: failed` timed out.
  The standalone run was 9/9 and the other 8 boots here
  passed. Clean re-run PASS (chunkhuge included).

## Incidents during the run

- VM replacement mid-Phase-B (during `cp`): /usr/bin
  tools wiped and the chained runner killed, but
  `~/workspace` survived intact (ISO hash re-verified
  `a2a4dbae…`, results.txt intact, fixtures intact).
  The runtime's os-intent replay restored QEMU 8.2.2,
  GRUB 2.12, and xorriso 1.5.6 on its own; the run was
  resumed from results.txt (runner skips PASS suites)
  with zero green suites lost. A second, smaller
  lesson from the same run: editing `run_regression.sh`
  while a chain was reading it produced a torn read
  (`haseD ;;` syntax error at the end of phaseD); the
  file itself is intact (`bash -n` clean) and results
  were complete. Do not edit the runner mid-run.
- /tmp was 1% at ship time (48K used). No /tmp
  exhaustion in this run (regression workdirs live
  under `~/workspace/nxtsOS-regression-v1.1.4/`).

## Host-side evidence (not QEMU suites)

- `tests/host_http_sec.c`: adversarial HTTP-helper
  tests 83/83 (status/header/CL/TE/chunked/cookie/
  redirect rules; overlong, duplicate, hostile inputs).
  Full read of `net/http.c` found no exploitable bug;
  see `releases/v1.1.4/SECURITY_REPORT.md`.
- `tests/qemu_test_http_sec.py`: hostile-peer QEMU
  tests 9/9 (userinfo, bad ports, overlong targets,
  overlong cookie, huge chunk, Secure-over-plain-HTTP —
  all refused with exactly the expected peer request
  counts, no panic).
- `tests/host_pss.c`: RSA-PSS verify PASS on a fresh
  generated vector (see above).
- `tests/host_der_tlv.c`: DER length parsing 11/11
  (the v1.1.3 `der_tlv` fix still holds).

## NOT TESTED (honest)

Live Vercel guest fetch from the kernel (peer-harness proof
only); user-side Virt-Manager retests (repo commands,
desktop fixes, Phase 2 TLS 1.3, and now Phases 3–4);
Bochs re-run for v1.1.x trees; real-pointer mouse
movement/clicking (scripted injection only); real
hardware; tampered-CertificateVerify negative (not yet
built); legacy against a real old server (hand-rolled
peers only); Phase 4 vs real web servers (peers
hand-rolled); Web Legacy toggle click itself (no PS/2
click delivery in the harness — the toggle shares the
shell-proven `tls_legacy_once` mechanism).
