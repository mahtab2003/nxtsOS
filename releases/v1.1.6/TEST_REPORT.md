# nxtsOS v1.1.6 — Test report

- Version: 1.1.6 (accumulation release over v1.1.5: Linux-comparability
  + deep-core + all five core redesigns — see MANIFEST.md).
- Date: 2026-11-02.
- Release ISO: `build/nxtsOS.iso`, 5,687,296 bytes,
  SHA-256 `2f53912c3985200d4ceaff4c5354c62dd87624bdabee4070868b8e285813871d`.
- Kernel binary: `build/nxtsOS.bin`, 563,812 bytes (at build time).
- Tested on: QEMU 8.2.2 (serial + VNC suites). Bochs 2.7 was NOT
  re-run for v1.1.6 (last Bochs pass: v0.10.0); real hardware was
  NOT tested; live Vercel fetch was NOT tested; user retests and
  real keyboards were NOT tested.
- Gate result: 120/120 suites PASS on the release ISO (latest
  result per suite; chain directory
  `~/workspace/nxtsOS-regression-v1.1.6c`, runner
  `run_regression.sh all`, phases A–F).

## Gate history: two genuine kernel bugs found and fixed during this gate

Neither bug was shipped over. Both were found by the gate chain,
fixed in the kernel, and the full chain was re-run on the rebuilt
ISO (hash change recorded below).

### Bug 1 — LAPIC publish-before-map race (kernel panic, rare boot)

- Symptom: chain run 1, `repo_httpsa` good boot: kernel panic
  early in boot, right after `Interrupts enabled`, before any
  `SMP:` line: `EXCEPTION 14 err=0x0 eip=0x101B2C`,
  `PAGE FAULT at 0xFEE00020`, `KERNEL PANIC: unhandled CPU
  exception`.
- Root cause (proven by disassembly): the faulting instruction
  was in `smp_cpu_index` (`mov 0x20(%edx),%edx`, LAPIC ID
  register). `kernel/smp.c: smp_init()` assigned
  `lapic_base = base;` BEFORE `vmm_map_page(...)` installed
  the LAPIC mapping. The PIT IRQ0 handler calls
  `smp_cpu_index()` on every timer tick; a tick landing
  between the store and the mapping faulted in IRQ context.
  Interrupts are enabled before `smp_init()` in
  `kernel/main.c`, so the window was live. Rare (one boot in
  ~100+), but genuine.
- Fix: map first, then publish, in `smp_init()`:
  `vmm_map_page(...)`, `invlpg(base)`, then
  `lapic_base = base;`, then `lapic_enable()`. A tick in the
  window now sees `lapic_base == 0` and returns 0 safely;
  after the store the mapping already exists. Verified in the
  rebuilt binary (map call before the store to `lapic_base`).
- Re-verified: `repo_httpsa` PASSED on the rebuilt ISO, and on
  the final ISO.

### Bug 2 — sysupdate snapshot stack overflow corrupting `.rodata.str1.1`

- Symptom: `sysupdate` suite boot 3 failed only on
  `FAIL: found hello 1.0`. All other boot-3 checks passed,
  including `Rolled back to the previous version` and
  `already installed (same version)` — hello 1.0 WAS installed
  after rollback; only the `pkg list` display failed. Serial
  log showed `Unknown command: pkg` (raw bytes clean).
- Localisation (interactive repro): the trigger is NOT
  `sysrollback`. Sequence `sysupdate bundle_good.nxupd` →
  `pkg list` WORKS → `sysupdate bundle_up.nxupd` (upgrade hello
  1.0 → 1.1) → `pkg list` FAILS already and stays broken
  (bare `pkg`, `pkg avail`, `help pkg` all fail). A plain
  `pkg install` upgrade does NOT break it — the trigger is
  specific to the sysupdate (snapshot) path.
- Proof: bare `help` after the breaking upgrade printed group
  names `fs`, `pkg`, `net` as empty strings while descriptions
  survived; QEMU monitor probes showed the `help_groups`
  pointers intact but the literal region zeroed; before/after
  `pmemsave` dumps diffed against the kernel binary showed
  `.rodata.str1.1` corrupted over `0x17ba7c–0x17be76` with
  stack-frame-like content (return addresses resolving to
  `ata_pio_read_sector`, `ata_pio_write_sector`, `blk_poll`,
  `irq_handler`, `isr19`). The killed literals are
  compiler-merged suffixes: `fs` is the tail of `cap_fs`,
  `pkg` of `cap_pkg`, `net` of `cap_net` (from
  `kernel/caps.c: cap_names[]`).
- Mechanism: kernel stack overflow. `kernel/pkg.c` had three
  8 KiB STACK journal arrays (`snap_delete_old` `jb[8192]`,
  `snap_take` `jb[8192]`, `snap_restore` `jb[8192]`), and
  `snap_take` calls `snap_delete_old`, nesting 8 KiB + 8 KiB
  under the shell-loop + `execute` frames (grown by the
  redesign-5 shell) + `pkg_sysupdate` + fs frames, past the
  16 KiB kernel stack (BSP stack `0x17c880–0x180880`).
  The v1.1.5 sysupdate suite passed because the older, smaller
  shell left just enough margin; the redesign-5 shell growth
  removed it.
- Fix: the three journal arrays are now file-scope statics
  (`snap_del_jb`, `snap_take_jb`, `snap_restore_jb`, separate
  buffers per function because `snap_take` calls
  `snap_delete_old`), and all four `sizeof(jb)` sites were
  updated to the static names (a pointer `sizeof` would have
  capped journals at 3 bytes). Logic otherwise unchanged.
- Re-verified: the full repro sequence (bundle_good → upgrade
  → rollback → `pkg list`, `help`, `help pkg`, `fs ls`)
  passes with zero `Unknown command` lines, and the `sysupdate`
  suite PASSED on the final ISO.

### Step 1 (pre-gate, test-only): smp suite pacing

`tests/qemu_test_smp.py` was hardened before this gate
(`send_verified_slow` + `sh_slow`, affinity call site only,
no assertion changed) and re-ran 52/52 PASS. The smp suite
passed 52/52 on the final ISO as well.

### ISO hash history across the gate

- Original redesign ISO: 5,687,296 bytes,
  `b5dbc8bb2b917d9881ba5bbfb86ab21bd70eb7449ab927f155c6b516990231e7`
  (kernel 563,908 bytes).
- After the LAPIC fix: 5,687,296 bytes,
  `111d9445638b610777541b4f47eede174215de737dba322c79d554a2a15bcc69`
  (kernel 563,908 bytes).
- After the snapshot-stack fix (RELEASE ISO): 5,687,296 bytes,
  `2f53912c3985200d4ceaff4c5354c62dd87624bdabee4070868b8e285813871d`
  (kernel 563,812 bytes — 96 bytes smaller: the journal arrays
  moved from stack to .bss). The full chain below ran on this
  ISO, and only this ISO. A VM replacement during the gate
  wiped `/usr/bin/qemu-system-x86_64` (and `/tmp`); QEMU 8.2.2
  was restored from the apt cache and the ISO hash was
  re-verified unchanged before testing resumed.

## Redesigned suites (internal check counts on the final ISO)

- vfsdirs: 82/82 checks, 0 FAIL lines.
- block: 30/30 checks, 0 FAIL lines.
- sockets: 36/36 checks, 0 FAIL lines.
- smp: 52/52 checks, 0 FAIL lines.
- redesign5: 79/79 checks, 0 FAIL lines.

## Harness flakes cleared by serial evidence + clean re-run (no suite weakened)

- `files_sysupd` (chain run): the desktop sysupdate flow
  itself passed (confirm → applied → same-version refusal →
  returned rc=0); the follow-up shell `pkg list` was typed as
  `pkg llist` (doubled `l`, the documented QEMU monitor
  sendkey-doubling class). Cleared by a clean re-run PASS.
- `http` (chain run): 22/23 sub-checks passed; only
  `cookie-main` timed out because `cookies clear` was typed
  as `cookies cllear` (doubled `l`), so the clear never ran
  and `(no cookies stored)` never appeared. The cookie
  machinery itself worked (`/set` → SET-OK, `/check` →
  CHECK-OK, `cookies list` showed the cookie, `/check2` →
  CHECK2-OK, `https-cookie` passed). Cleared by a clean
  re-run PASS (23/23).
- `redesign5` (chain run): 78/79; only the Ctrl-C typed-ahead
  check failed. The check snapshots the log the moment the
  post-interrupt prompt appears, with no wait for the echo
  output — a poll race. The final serial log proved the
  behaviour correct: `interrupted (SIGINT)` → prompt →
  `echo intact` → `intact`, in order. Cleared by a clean
  re-run PASS (79/79).
- `parity_fg` (chain run + re-runs): the bare-`wait` check
  (`wait` with no argument must report 2 jobs: 4 `wait: job`
  lines + 2 `exit status` lines) failed repeatedly, with the
  wait-all leftover check failing twice as a downstream
  cascade. Segment dumps from a debug copy (identical logic
  plus prints after capture) proved the mechanism: the
  harness's `send_verified` echo check is blinded when a
  background job's print lands mid-typing, so it erases and
  retypes; a blinded `runbg` send can burn ~14 s in retries,
  during which the first 10-second `slow10` job expires, so
  only one job is visible at bare-`wait` time — and the kernel
  then correctly reports exactly that one visible job
  (done + exit status 0). The kernel's wait semantics were
  also proven directly: a 3-job bare `wait` reported all
  three jobs correctly. This is the same slow10-expiry
  failure class the smp suite already worked around by
  switching to 60-second `longrun` jobs; the parity_fg
  harness still uses 10-second `slow10` jobs for this pair,
  so the check stays timing-sensitive (follow-up for the
  harness, not a kernel change, and not a gate blocker once
  cleared). The unmodified suite passed cleanly multiple
  times on the release ISO (including the official runner,
  which records the final PASS below).

## Full per-suite tally (latest result per suite, release ISO)

- anchor_stop: PASS
- audit_cap: PASS
- audit_log: PASS
- base: PASS
- block: PASS
- calc: PASS
- castore: PASS
- cat_large: PASS
- chmod: PASS
- core_edit: PASS
- core_fw: PASS
- core_hw: PASS
- core_power: PASS
- core_users: PASS
- cp: PASS
- deepcore2: PASS
- deepcore: PASS
- desktop10: PASS
- desktop10sec: PASS
- desktop: PASS
- desktop_apps: PASS
- desktop_expose: PASS
- desktop_fallback: PASS
- desktop_logout: PASS
- desktop_noconsole: PASS
- desktop_nonic: PASS
- desktop_reboot: PASS
- desktop_sec: PASS
- desktop_unlock_audit: PASS
- desktop_unlock_nonroot_audit: PASS
- desktop_web: PASS
- enc: PASS
- enc_sec: PASS
- files_chmod: PASS
- files_hash: PASS
- files_install: PASS
- files_run: PASS
- files_sysupd: PASS
- gui_sec: PASS
- host_der_tlv: PASS
- host_ec256: PASS
- host_http: PASS
- host_http_sec: PASS
- host_legacy_crypto: PASS
- host_pss: PASS
- http: PASS
- http_sec: PASS
- idle_lock: PASS
- legacy: PASS
- linuxcomp2: PASS
- linuxcomp: PASS
- monitor_disk: PASS
- monitor_jobs: PASS
- mv: PASS
- net: PASS
- net_peer: PASS
- net_sec: PASS
- network_dns: PASS
- network_ping: PASS
- newapps: PASS
- packages_remove: PASS
- packages_rollback: PASS
- parity1: PASS
- parity2: PASS
- parity_fg: PASS
- parity_pipe: PASS
- parity_shell: PASS
- parity_text: PASS
- passwd: PASS
- phase5: PASS
- phase5_sec: PASS
- pkg: PASS
- pkg_sec: PASS
- pkgsig: PASS
- redesign5: PASS
- repo: PASS
- repo_avail: PASS
- repo_bench: PASS
- repo_desktop: PASS
- repo_fetch: PASS
- repo_https: PASS
- repo_httpsa: PASS
- repo_root: PASS
- repo_scroll: PASS
- repo_set: PASS
- repo_sysinfo: PASS
- scroll: PASS
- settings_unlock: PASS
- shell_echo: PASS
- shell_groups: PASS
- shell_idle_lock: PASS
- smp: PASS
- sockets: PASS
- source_check: PASS
- storage: PASS
- storage_sec: PASS
- storm: PASS
- sysupdate: PASS
- tamperedcv: PASS
- tls13: PASS
- tls13_tampered: PASS
- tls13_wrappedcert: PASS
- tls: PASS
- tls_alpn: PASS
- tls_anchor: PASS
- tls_chain: PASS
- tls_ecdhe: PASS
- tls_hostmatch: PASS
- tls_peer: PASS
- tls_ske: PASS
- topk: PASS
- unlock_nouser: PASS
- user: PASS
- v041: PASS
- v041_sec: PASS
- v071: PASS
- vfsdirs: PASS
- web_save: PASS
- webpanic: PASS
- webpanic_desktop: PASS
