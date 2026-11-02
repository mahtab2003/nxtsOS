# nxtsOS v1.1.6 — Security report

- Version: 1.1.6. Date: 2026-11-02.
- Scope: the new surfaces from the core-redesign run —
  VFS/directories, block layer, sockets, SMP, paging/VMA,
  capabilities — plus the gate findings. Verdicts below are
  code-review verdicts confirmed by the final-ISO suites
  (vfsdirs 82/82, block 30/30, sockets 36/36, smp 52/52,
  redesign5 79/79, plus the security suites, all PASS on the
  release ISO — see TEST_REPORT.md). No exploitable finding
  is left unaddressed in this release.

## VFS/directories — CLEAN (no exploitable finding)

- `fs/nxtsfs.c: walk_comps` requires read permission on every
  intermediate directory (non-root → `can_read_entry`, else
  `-3`); root is always open.
- Symlink hop budget 4 per whole path resolution
  (`hops >= 4` refuses; loop/dangling → `-1`); lexical
  `..`/`.` resolution with malformed-path refusals (empty
  components, trailing slash, `//`); component ≤ 31 chars,
  ≤ 16 after resolution, path ≤ 255.
- `parent_writable` gates creates; `fs_link_path` refuses
  directories (`flags & 8` → `-7`), FIFOs, and bare links,
  requires source readability + writable parent + no
  existing target.
- Hard-link sector freeing is scan-based:
  `free_sectors_scanned` frees only when no other valid
  non-link entry shares `start_sector`.
- `fs_chown_as`/`fs_chgrp_as` are root-only in the fs layer,
  not just the shell; `can_read_entry` handles owner/group/
  other triples, and `audit.log` is never readable by
  non-root.

## Block layer — CLEAN

- `drivers/blk.c`: file-scope statics only (queue, order
  list, test buffers); `blk_enqueue` validates `dev == 0`,
  non-null buffer, `1 ≤ count ≤ BLK_MAX_GROUP` (64),
  direction; queue cap 16 (`BLK_QUEUE_CAP`); merging only
  adjacent same-device/same-direction contiguous-LBA +
  contiguous-buffer requests, capped at `BLK_MAX_GROUP`,
  with single-sector PIO fallback counted on multi failure.
- `fs_fsck` verified read-only: its body contains no
  `ata_write`/`write_sector`/`save_dir`/`bit_set` calls — it
  reads superblock/bitmap/directory and reports
  inconsistencies, never repairs.
- Swap slots exist (`blk_swap_alloc`/`blk_swap_free`,
  file-scope) but no backing area is configured, so no
  page-out ever happens (documented as inactive; `swapon`
  refuses, `swapoff` reports nothing active).

## Sockets — CLEAN

- `net/sock.c` + `net/net.c`: the firewall hook runs in IP
  receive AFTER src/dst/proto parsing and dst validation but
  BEFORE any dispatch (`fw_check(0, …)` in `net_rx_frame`;
  outbound `fw_check(1, …)` at send).
- Privileged ports are root-only at BOTH `sock_bind` and
  `sock_listen` (`port < 1024 && uid != 0` → `-2`); shell
  `srv` paths pass `session_uid` (plus a `cap_net` gate for
  root with the capability dropped), and syscalls pass
  `p->uid` (`SYS_BIND`/`SYS_LISTEN` in `kernel/syscall.c`);
  per-process fd ownership is enforced via `fd_sock_index`.
- Backlog clamped to `SK_BACKLOG_MAX` (4); backlog-full sends
  RST and frees instead of queueing invisibly; listener
  close frees queued + half-open children (collected first,
  small 64-byte stack array) while accepted children survive
  detached.
- RX bounds: `ip_len < ihl + 20` rejected, `doff`
  bounds-checked, `seg_len > 1500` dropped, TCP checksum
  verified into file-scope `sock_vbuf` (IP layer already
  validates `ihl ≥ 20`, total ≤ plen, header checksum, no
  fragments); TCP take bounded by actual window room
  (`SK_RX_SIZE` 4096, advertised window = free room),
  straddling retransmits take only the new tail, never
  overwrite buffered bytes; stray SYN on an established
  connection only re-ACKs; UDP length validated
  (`8 ≤ udp_len ≤ ip_len - ihl`), queue of one datagram
  (second dropped but counted), oversize truncated to
  `SK_RX_SIZE`. Table-full SYN → drop (no allocation).
- Documented known limits (NOT findings): predictable ISNs
  (timer + counter), single fixed retransmit timer,
  one-datagram UDP queue, poll-based user reads.

## SMP — CLEAN (one race found and fixed during the gate)

- `kernel/spinlock.h`: xchg-based spinlocks with
  irqsave/irqrestore, documented lock order
  (`bg_lock → kmalloc_lock → pmm_lock`), never taken in IRQ
  handlers / across sleep / nested against the order;
  console lock is owner-recursive and never taken under
  bg/pmm/kmalloc locks.
- AP: LINT0 masked (`0x10000`) so the 8259 never interrupts
  the AP (the earlier AP-IRQ0/preempt corruption root
  cause); readiness signal (`ap_state_v = 2`) set only after
  AP LAPIC/TSS setup and before `sti`; AP timer off →
  `pause` loop instead of `hlt`.
- `smp_cpu_index` returns 0 when `lapic_base == 0`; BSP id
  wins ties.
- GATE FIX (see TEST_REPORT.md): `smp_init()` published
  `lapic_base` before installing the LAPIC mapping, so a
  timer tick in the window faulted in IRQ context
  (proven panic, chain run 1). Fixed map-before-publish;
  verified in the rebuilt binary and by `repo_httpsa` PASS
  on the final ISO.

## Paging/VMA — CLEAN

- `mm/vma.c`: `vma_add` requires page alignment,
  `1 ≤ pages ≤ 16`, no unknown flag bits, address ≥
  `KERNEL_MAP_END`, end ≤ `USER_STACK_PAGE` with
  overflow-safe arithmetic, and refuses overlap with code,
  brk heap, stack page, or existing VMAs.
- `vma_contains_range` has an overflow guard
  (`ptr + len < ptr` → 0). `vma_handle_fault` maps only
  in-VMA pages, zeroes the fresh frame, uses `invlpg`, and
  on OOM fails the process (returns 0), never panics.
- `kernel/syscall.c: valid_user_range` accepts only
  code/stack/brk-heap/VMA ranges with the same overflow
  guard.

## Capabilities — CLEAN (with one documented non-enforcement)

- `kernel/shell.c: session_caps = CAP_ALL` for root, 0
  otherwise; `sh_cap_gate` enforces root-only + capability
  bit + `mac_check` for audit/sys/user/fs/pkg/net-gated
  commands (shutdown, halt, user/group ops, chown/chgrp,
  sysupdate/sysrollback, pkg install/repo/update/fetch/
  remove, dhcp/dnsset, castore, fw, hostname/dmesg, log).
- `mac_check` in `kernel/caps.c` is explicitly a NO-OP hook
  (returns 0, documented as "must never be read as
  enforcement") — the real gates are the root/cap checks,
  so this is not a vulnerability, but it must be described
  honestly, not as MAC enforcement. The `mac` command
  reports "no policy engine" for the same reason.
- The `sudo`-style path grants `CAP_ALL` only after
  authentication (by design, root password path).

## Gate fix with security impact — snapshot stack overflow

- The sysupdate snapshot journal arrays (8 KiB each, on the
  16 KiB kernel stack, nested) overflowed the stack and
  scribbled over `.rodata.str1.1`, killing the `fs`/`pkg`/
  `net` command-group names (see TEST_REPORT.md). This was
  a genuine memory-safety bug: a deeper path could also
  have reached `.data` globals. Fixed by moving the three
  journal arrays to file-scope statics with corrected
  sizes; verified by the full sysupdate sequence and the
  `sysupdate` suite PASS on the final ISO.
- Follow-up (NOT part of this gate fix, NOT on the sysupdate
  chain): `fs/nxtsfs.c: fs_append` has a 4 KiB stack array
  `u8 old[4096]` on the audit-log path. It is left as-is
  and noted here for a later hardening pass. The deepest
  remaining chain after the fix is roughly 1–2 KiB
  (`registry_load`/`registry_save` 2049-byte buffers and
  `pkg_install`'s ~1 KiB manifest, sequential, not nested
  with the journal buffers).

## Release notes

- No exploitable finding is left unaddressed. The two gate
  bugs (LAPIC race, snapshot stack overflow) were found by
  the gate, fixed, and re-verified on the release ISO.
- The package signing key (`build/signing.key`) never ships
  in any archive. The compiled-in vendor public key ships as
  generated source (`kernel/vendor_pubkey.h`) so
  vendor-signed packages verify.
- Developer audit/test commands are present in v1.1.6 as in
  v1.1.5 (they are how the suites run); a release profile
  that strips them from release builds is post-v1.1.6 plan
  work, not claimed here.
- Legacy web/SSL (SSLv2/v3, TLS 1.1) remains opt-in only,
  never default, never auto-downgrade, never for the
  package repo.
