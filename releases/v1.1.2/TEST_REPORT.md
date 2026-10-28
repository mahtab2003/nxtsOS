# nxtsOS v1.1.2 — Test report

Release ISO: 5,390,336 bytes,
SHA-256 `4291f1ccd27a13837562956df0b8337acfb3cc6355bf215c01bdaaea0bffcf06`.
All suites below ran against this ISO on QEMU 8.2.2 (serial +
VNC harnesses). Build: OK, 7 pre-existing warnings (unchanged
from v1.1.1: RWX calc/term/kernel bin, misleading-indentation in
wm.c, `draw_window` unused, two unused-variable lines including
`net/tls.c:418` 'end').

## Result: 76/76 PASS

- Phase A (core + security + desktop + net + repo): 28/28 PASS
  (base, storage, storage_sec, phase5, phase5_sec, v041, v041_sec,
  pkg, pkg_sec, pkgsig, sysupdate, enc, enc_sec, gui_sec, desktop,
  desktop10, desktop_apps, desktop10sec, desktop_web,
  desktop_nonic, desktop_sec, calc, net, net_peer, tls, net_sec,
  repo, v071).
- Phase B (post-v1.1.0 features): 48/48 PASS (anchor_stop,
  tls_chain, desktop_fallback, shell_echo, tls_ske, storm,
  tls_anchor, tls_hostmatch, tls_alpn, tls_ecdhe, tls_peer,
  repo_https, repo_httpsa, repo_avail, repo_bench, repo_fetch,
  repo_set, repo_scroll, repo_desktop, repo_root, repo_sysinfo,
  files_run, files_install, files_hash, files_chmod, files_sysupd,
  packages_remove, packages_rollback, monitor_jobs, monitor_disk,
  network_dns, network_ping, desktop_logout, desktop_reboot,
  desktop_unlock_audit, desktop_unlock_nonroot_audit,
  settings_unlock, unlock_nouser, idle_lock, shell_idle_lock,
  audit_cap, audit_log, cat_large, passwd, cp, mv, chmod,
  web_save).

## The fix, proven

- New suite `tls_anchor_stop` (8/8 on the release ISO): a peer
  harness serves the EXACT live 3-cert chain (leaf + WR1 + 4096-bit
  R1, captured from nxtsos-repo.vercel.app). repo-good succeeds
  end to end (index updated, 2 packages v1, sysinfo installed and
  run); repo-badanchor, repo-badsig, repo-wronghost, repo-expired
  refuse; live-anchored and live-tofu with the exact live DERs
  pass certificate verification (guest ClientKeyExchange
  observed — a full handshake is impossible without the leaf
  private key, so the guest then prints a generic "failed", NOT
  "certificate refused"); live-wronghost refuses with no
  ClientKeyExchange.
- Pre-fix ISO (v1.1.1 tree, `4c4b3cf4…`) failed exactly as
  diagnosed: repo-good, live-anchored, and live-tofu all refused
  with "certificate refused" and no ClientKeyExchange; all
  negatives refused correctly.
- `repo_httpsa` (anchored repo path) and `repo_https` (TOFU repo
  path) both PASS on the release ISO, as do `tls_anchor` (3/3),
  `tls_chain` (5/5), `tls_ske`, `tls_ecdhe`, `tls_peer`,
  `tls_hostmatch`, `tls_alpn`, and `tls`.

## First-run failures: all harness, none kernel

The first full pass showed 8 Phase A + 4 Phase B failures. Every
one was diagnosed from its log and cleared on a clean re-run; no
kernel code changed in response to any of them:

- storage: the regression fixture disk lacked the `hello.txt`
  the test cats for its "Hello from nxtsFS" marker (write /
  reboot / readback all passed). Fixture fixed.
- pkg: the `hello11.nxpkg` fixture contained the 1.0 ELF instead
  of the 1.1 ELF (`hello2.elf`), plus one `ppkg` sendkey-doubling
  flake. Fixture fixed; re-run clean.
- pkgsig, sysupdate, storm: QEMU monitor sendkey-doubling flakes
  (`helllo.elf`, `helllo.elf`, `stormtestt`) in tests that type
  once without echo-retry. Proven from the serial logs; clean
  re-runs pass.
- pkg_sec, calc, enc, enc_sec: the runner omitted caller-built
  disks these tests require (pkg_sec disk from the setup's
  packages; calc needs the desktop-sec setup disk; enc needs an
  `mkdisk_enc` encrypted disk; enc_sec needs a plain disk).
  Runner fixed. (One subtlety found while fixing enc: the test's
  docstring lists a loose `hello.elf` on the disk, but the
  kernel's installer correctly refuses to overwrite an existing
  file, so the encrypted disk must carry only `hello.nxpkg`;
  the installed file then satisfies the run check.)
- tls_anchor, tls_hostmatch, tls_alpn: the runner ran the tests
  from the wrong working directory, so their relative
  `tools/mkdisk.py` calls failed. Runner fixed (cd to repo root).
  Note: the runner's results file is append-only, so its final
  summary grep lists stale FAIL lines; the per-suite LATEST line
  is the true verdict (48/48).

## NOT TESTED (honest list)

- Live Vercel guest fetch from the kernel (sandbox blocks guest
  DNS over slirp UDP; peer-harness proof only). User-side retest
  on real QEMU/KVM via Virt-Manager is the key remaining live
  proof: `pkg repo https://nxtsos-repo.vercel.app/` +
  `pkg update`, and the `httpsa://` variant.
- Bochs re-run (last pass v0.10.0); real-pointer mouse; real
  hardware; Android Bochs / VirtualBox.
- NOT IMPLEMENTED (unchanged): graphical boot login, installer,
  UEFI, TLS 1.3 / ECDSA certificates / general CA store /
  4096-bit RSA verification for links that must actually be
  verified, user-mode socket API, multi-connection TCP, package
  revocation list, multi-generation rollback, HTML rendering.
