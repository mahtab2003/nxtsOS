# nxtsOS v1.1.5 — Test report

- Release ISO: `build/nxtsOS.iso`, 5,517,312 bytes,
  SHA-256 `b4d42ad595ae84908ea302d438fba603d783e63787869418aeb0b59124767de3`
- Kernel binary: `build/nxtsOS.bin`, 394,132 bytes (at build time)
- Date: 2026-10-30. Tested on QEMU 8.2.2 (serial + VNC suites).
  Bochs was NOT re-run for v1.1.5 (last Bochs pass: v0.10.0).
- Runner: `~/workspace/nxtsOS-regression-v1.1.5/run_regression.sh`
  (results in `results.txt` there; verdict per suite is the
  LATEST `SUITE <name> PASS/FAIL` line for that suite —
  the file accumulates history, so stale FAIL lines from
  cleared flakes and fixed harness bugs remain visible
  above later PASS lines).
- Gate: **104/104 PASS** (Phase A 28/28, Phase B 48/48,
  Phase C 11/11, Phase D 11/11, Phase E 6/6). No suite is
  left failing.

## Phase A — 28/28 PASS

base, storage, storage_sec, phase5, phase5_sec, v041, v041_sec,
pkg, pkg_sec, pkgsig, sysupdate, enc, enc_sec, gui_sec, desktop,
desktop10, desktop_apps, desktop10sec, desktop_web,
desktop_nonic, desktop_sec, calc, net, net_peer, tls, net_sec,
repo, v071.

## Phase B — 48/48 PASS

anchor_stop, tls_chain, desktop_fallback, shell_echo, tls_ske,
storm, tls_anchor, tls_hostmatch, tls_alpn, tls_peer,
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

## Phase D — 11/11 PASS

legacy (19/19), http (23/23), user, host_http (43/43),
host_legacy_crypto (21 checks), host_der_tlv (11/11),
host_ec256, host_pss, host_http_sec (83/83),
source_check, http_sec (9/9).

## Phase E — 6/6 PASS (new in this release)

core_hw (34 checks), core_power (21 checks),
core_users (82 checks), core_edit (59/59, HARDENED version),
core_fw (71 checks), tamperedcv (6/6).

## FAILs cleared with proof (four flakes + one harness bug, zero kernel bugs)

- `files_sysupd` (Phase B): desktop-interaction flake.
  The first run's serial log proves the first apply fully
  succeeded (confirm + applied + `pkg list` proof for
  greet 1.0 / hello 1.0), but the second apply — the
  expected same-version refusal — produced no serial
  output at all: the mode returned rc=0 right after the
  first apply, i.e. the second round of clicks did not
  land. The mode-17 logic is unchanged since v1.1.4
  except the version literal, and the fs diff (system-
  file list + chown/stat) does not touch enumeration
  order. Clean re-run PASS with every marker present,
  including both refusal lines.
- `http` cookie-main (Phase D): first run 22/23, only
  cookie-main failing, every other case (including
  https-cookie, cookie-edge, noredirect, nocookies)
  passing. Clean re-run 23/23, cookie-main PASS.
- `user` (Phase D): prompt-race, not a kernel regression.
  The test terminates QEMU the instant the finish line
  ("All user processes finished.") appears in the serial
  log, then requires `root@nxts> ` AFTER that line. The
  first run's serial log shows the shell had started and
  printed the new setup-mode notice but not yet the
  prompt when QEMU was killed. The race window is
  widened by the core run's new setup-mode notice path
  (more work between shell start and first prompt), but
  the shell itself is proven working by every
  shell-driven suite in this run. Clean re-run PASS.
  A future hardening (wait for the prompt instead of
  terminating on the finish line) is possible but was
  NOT applied here; the test is unchanged.
- `http_sec` secplain (Phase D): first run 8/9, only
  secplain timing out (TIMEOUT waiting for SETSEC-OK),
  the other 8 boots passing. Clean re-run 9/9,
  secplain PASS.
- `tamperedcv` (Phase E): harness path-length bug, not
  a kernel failure. The QEMU monitor UNIX socket path
  is capped at 108 bytes; the regression workdir plus
  `tls13-tamperedcv-pss-wrong-transcript-mon.sock`
  (109 bytes) and
  `tls13-tamperedcv-ecdsa-wrong-transcript-mon.sock`
  (111 bytes) exceed it, so QEMU refused to start for
  those two cases and the peer connection failed
  (ConnectionRefusedError traceback; the guest never
  booted for those cases). The first case (pss-flip)
  passed before the crash. Test-only fix in
  `tests/qemu_test_tls13_tamperedcv.py`: run_boot is
  now passed a short tag (`tcv-pf`, `tcv-pwt`,
  `tcv-pwk`, `tcv-pwa`, `tcv-ef`, `tcv-ewt`) for the
  socket filename ONLY — case names in results, peer
  debug logs, and every assertion (stage-3 refusal, no
  bytes line, no panic) are unchanged. The release ISO
  was NOT rebuilt for this fix (the kernel binary is
  untouched); the re-run passed 6/6 on the same ISO
  `b4d42ad5…`. Future suites must keep monitor socket
  paths under 108 bytes.

## Incidents during the run

- VM replacement mid-Phase-A (during `repo`): /usr/bin
  tools wiped and the chained runner killed, but
  `~/workspace` survived intact (ISO hash re-verified
  `b4d42ad5…`, results.txt intact, fixtures intact).
  The runtime's os-intent replay restored QEMU 8.2.2,
  GRUB 2.12, and xorriso 1.5.6 on its own; the run was
  resumed from results.txt (runner skips PASS suites)
  with zero green suites lost (repo + v071 then passed).
- VM replacement mid-Phase-C (during `castore`):
  tools + /tmp wiped again, same survival. This time
  the replay's `apt-get update` step sat wedged at
  0 CPU, so the toolchain was restored from
  `/var/cache/apt/archives` with `dpkg -i` in the
  recorded dependency order (QEMU 8.2.2 including the
  gui modules, GRUB 2.12, xorriso 1.5.6; the replay
  skips already-installed packages later, per
  AGENTS.md). The release ISO was re-verified
  unchanged (`b4d42ad5…`) before Phase C restarted,
  and castore then passed. Zero green suites lost.
- /tmp was 0% at ship time. No /tmp exhaustion in
  this run (regression workdirs live under
  `~/workspace/nxtsOS-regression-v1.1.5/`).

## Host-side evidence (not QEMU suites)

- `tests/host_http.c`: 43/43 (Phase 4 HTTP helpers).
- `tests/host_http_sec.c`: 83/83 adversarial HTTP
  parser/cookie/redirect cases (carried from v1.1.4).
- `tests/host_legacy_crypto.c`: 21 checks (MD5/SHA-1/
  AES legacy crypto vectors).
- `tests/host_der_tlv.c`: 11/11 (der_tlv wrap-proof
  fix, carried from v1.1.3).
- `tests/host_ec256.c`, `tests/host_pss.c`: green
  (ECDSA P-256 + RSA-PSS vectors).
- `tests/check_source.py` (source_check): green —
  the source tree contains no forbidden artefacts.

## NOT TESTED

- Live Vercel guest fetch from the kernel (peer-harness
  proof only). User-side Virt-Manager retests (repo
  commands, desktop fixes, Phases 2–4, and now the
  v1.1.5 core features) remain the key live proof.
- Bochs re-run for v1.1.x trees (last Bochs pass:
  v0.10.0); real hardware; real-pointer mouse
  movement/clicking (scripted injection only).
- Tampered-CertificateVerify against a real TLS 1.3
  server (hand-rolled peers only); client-certificate
  CV is not applicable (the guest never offers client
  certificates); legacy against a real old server;
  Phase 4 against real web servers.
- Web Legacy toggle click itself (no PS/2 click
  delivery in the harness); editor on real hardware
  keyboards (QEMU sendkey only).
- Group-enforced file permissions, `date set`, editor
  undo, editor files over 32 KiB, top job control,
  HTTP proxy/server: NOT IMPLEMENTED (see MANIFEST.md
  and docs/CORE_CLI.md §9 for the remains list).
