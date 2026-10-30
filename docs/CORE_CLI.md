# nxtsOS Core CLI Completion — Design Record

User direction 2026-10-29 ~22:49 PKT: focus SOLELY on core; make the CLI
complete FIRST, then enhance the GUI desktop afterwards. No desktop/GUI
work in this run. Shipped as v1.1.5 on 2026-10-30 (104/104 regression
on release ISO b4d42ad5…; see releases/v1.1.5/TEST_REPORT.md).
This document is the durable design record (structured-working rule): what exists, what is missing,
the exact command surface, the data model, the security model, and the
test plan per family. Implementation follows this document only.

## 0. Audit: what the CLI already has (v1.1.4, kernel/shell.c)

Groups (10, pure): system, session, fs, proc, pkg, net, crypto, diag,
gui, test. Group dispatch works (`net ping`, `test csprngtest`, ...);
flat names work as aliases; bare `help` is a group index; every command
has a dedicated help entry.

- system: help, ver, mem (frames), ticks, clear, echo, reboot (keyboard
  controller, NO confirm, NO uid gate — load-bearing for the storage
  harness, see below).
- session: whoami, lock, unlock (root), passwd (root: any user; others:
  own only + current-password check; echo off; buffers cleared), logout,
  idle.
- fs: fs (status), ls (list view), cat (windowed), write, rm, mv, cp,
  chmod (octal, strict).
- proc: run, runbg, jobs (list view), kill (own jobs, or any as root).
- pkg: pkg list/avail/install/remove/repo/update/fetch, sysupdate,
  sysrollback (all mutating ops root-gated).
- net: netinfo, netdbg, dhcp (NO uid gate — pre-existing), ping, dns,
  dnsset (NO uid gate — pre-existing), http/https/httpsa/httpss
  (Phase 4: redirects, cookies, chunked), cookies, sslprobe, castore,
  tofprints.
- crypto: sha256 (file, 64 KiB cap).
- diag: fbinfo, kbdstat, mouse, mousepoll.
- gui: gui, desktop (OUT OF SCOPE for this run).
- test: ~40 autotest commands (OUT OF SCOPE except neighbours).

Underlying APIs confirmed by audit:
- users: MAX_USERS 8, users.txt `name:uid:salt:hashhex`, salted FNV-1a
  x10000 (NOT a production KDF — documented in docs/SECURITY.md).
  users_load/check/exists/change_password exist. NO add/delete API.
- fs (nxtsFS): FS_MAX_FILES 32, dir entry {size, start_sector,
  sector_count, uid, mode, flags} — NO group field (see §3 groups
  decision). Permissions are owner-vs-other only. fs_write_as on
  overwrite RESETS uid to the caller and mode to the passed mode —
  the editor save path must stat first and restore both (see §4).
  Writes are synchronous (sectors first, then bitmap + directory);
  there is no separate flush/sync step, so shutdown needs no fs
  flush. Valid names, sizes, and modes are bounds-checked, never
  fatal.
- console: 80x25 text buffer, VGA or framebuffer rendering, 100-line
  scrollback ring. Cursor position is module-static — the editor
  needs new console APIs (see §4). Serial always mirrors console
  output; the editor must NOT render through console_write (it
  would spam serial with a full redraw per keystroke).
- keyboard: PS/2 set 1, 256-entry int buffer. Only PgUp/PgDn are
  delivered as special codes; arrows and Ctrl are ignored. The
  editor needs arrow/Home/End/Del keys + Ctrl-letter codes (§4).
- network: polled e1000 driver; net_rx_frame parses Ethernet/IPv4
  and dispatches ICMP/UDP/TCP; net_ip_send builds IP packets.
  These are the two firewall hook points (§5).
- hardware: NO CPUID, NO PCI enumeration (fb.c and e1000.c each
  carry a private 0xCF8/0xCFC reader for their own device only),
  NO ACPI. ATA presence + raw sector I/O exist; fs total/free
  sector counts exist; PMM frame counts exist; PIT ticks exist.
- CMOS RTC read pattern exists (kernel/csprng.c: ports 0x70/0x71,
  NMI-disable bit) — reused for `date`.
- build.sh compiles an EXPLICIT kernel file list (compile loop +
  link list): every new .c file must be added to BOTH lists.
- Kernel stack is 16 KiB: all large buffers are file-scope statics.
  u64 division/modulo is FORBIDDEN.

## 1. Family (a) — Hardware control + resources (diag/system/proc)

Commands (all read-only, no uid gate — they disclose only the
machine's own configuration, not other users' data):
- `diag cpu` — CPUID: vendor string, brand string (if present),
  family/model/stepping, feature flags (FPU, TSC, MSR, APIC, SSE,
  SSE2, HTT, NX where reported). New kernel/hwinfo.c: cpuid wrapper
  (asm, leaf + subleaf, register outputs). No CPUID → "not available"
  (fail-closed message, never fabricated values).
- `diag pci` — PCI bus 0 scan, all 32 devices x 8 functions:
  vendor:device, class code, BAR0. Uses the same 0xCF8/0xCFC port
  pattern fb.c/e1000.c already use (a third local reader, NOT a
  refactor of those drivers — lower risk). Absent device (vendor
  0xFFFF) skipped silently. Multi-function handling: function 0
  header type bit 7 decides whether functions 1-7 are probed.
- `diag disk` — ATA presence, disk total/free sectors from the
  filesystem, sizes in MiB (sectors*512, u32-safe: disk is 16 MiB),
  file count (used slots / 32). Refuses cleanly when no disk.
- `system uptime` — ticks at 100 Hz → days/hours/minutes/seconds
  (repeated subtraction, no u64 division), plus background job
  count. (The existing `ticks` command is kept verbatim.)
- `system sysinfo` — one screen: version, CPU vendor (short),
  memory frames total/free/used, disk total/free, NIC MAC + IP
  (or "no NIC"/"no IP"), background jobs, session user, uptime.
- `proc ps` — session line (`user uid`) + background jobs list
  view (reuse of proc_bg_list's pinned row format).
- `proc top` — live monitor, ~1 s refresh: uptime, memory, disk
  free, net rx/tx/drops, background jobs (pid/name/uid). Reads
  keys via keyboard_poll; `q` quits (any other key ignored).
  Exits to a cleared screen with "top: quit". No job control
  from inside top in this run (kill stays a separate command).

Data model: none persisted. All values read live from hardware or
existing counters. Test plan: QEMU test boots (setup mode, no
disk for cpu/pci; seeded disk for disk/sysinfo), asserts vendor
string present (QEMU CPU), e1000 device present in pci output,
disk sizes sane, uptime format, ps/top rows + top quit.

## 2. Family (b) — Shutdown / power (system)

- `system shutdown [--force]` — root only (handler checks
  session_uid, like castore). Without --force: prints
  "Shutdown? (y/n)" and reads one line; anything but exactly
  "y" aborts with "shutdown: aborted" (fail-closed). Then
  "Powering off..." and ACPI poweroff (new kernel/acpi.c):
  RSDP search (EBDA pointer at 0x40E, then 0xE0000-0xFFFFF,
  "RSD PTR " signature + checksum), RSDT/XSDT walk for the
  FADT ("FACP"), PM1a control block + SLP_TYP from the FADT,
  then outw(PM1a, SLP_TYP<<10 | SLP_EN). If ACPI tables are
  absent or malformed: "shutdown: ACPI poweroff unavailable"
  and NO halt (fail-closed, never a fake poweroff). If the
  write returns (hardware did not power off): halt loop with
  "shutdown: poweroff failed, system halted".
- `system poweroff` — alias entry, same handler as shutdown.
- `system halt [--force]` — root only, same confirmation
  rule; prints "System halted." then hlt loop (CPU stopped,
  VM still present — the QEMU-visible proof is the message
  plus no returning prompt).
- `system reboot` — UNCHANGED: keyboard-controller reboot, no
  confirm, no uid gate. Reason: tests/qemu_test_storage.py
  types `reboot` and expects an immediate reboot; adding a
  prompt or gate would break that harness, and a local-console
  reboot is not a privilege boundary worth breaking a harness
  over. Recorded here as a deliberate carried exception, not
  an oversight.
- No fs flush step: nxtsFS writes commit synchronously (see
  §0), so shutdown has nothing to flush. The security report
  states this explicitly instead of inventing a flush.

Test plan: QEMU test, root session: `shutdown` + "n" aborts
(prompt returns); `shutdown --force` on QEMU ACPI powers the
VM off (QEMU process exits — the test asserts process exit,
the strongest possible proof); `halt` + "y" prints halted and
never returns a prompt; non-root `shutdown`/`halt` refused
with "root only" and the machine stays up.

IMPLEMENTATION NOTE (2026-10-30, as built — read this, not
the paragraph above, for the shipped behaviour):
- SLP_TYP comes from the DSDT `_S5_` package, not the FADT;
  the FADT supplies only PM1a/PM1b + SMI_CMD/ACPI_ENABLE.
- FADT OFFSET BUG, found and fixed during this run: the
  first build read PM1a_CNT_BLK from offset 56, but the
  table's layout is PM1a_EVT_BLK 56, PM1b_EVT_BLK 60,
  PM1a_CNT_BLK 64, PM1b_CNT_BLK 68 (proven twice over:
  QEMU `info mtree` shows evt 0x600 / cnt 0x604 / tmr
  0x608, and the FADT bytes at 64/68/76 read exactly
  0x604/0x0/0x608). The old code wrote SLP_EN to the PM1
  status register (write-1-to-clear), which silently did
  nothing, and its "SCI_EN check" read STS bit 0 (timer
  status, happened to be 1) instead of SCI_EN. Fix:
  `kernel/acpi.c` reads 64/68; the length gate is 72.
- The QEMU `_S5_` package is genuinely {0,0,0,0} (full
  DSDT dump, 6854 bytes, checksum valid; `_S3_`={1,1,0,0},
  `_S4_`={2,2,0,0} alongside it). SLP_TYP 0 + SLP_EN
  powers QEMU off once SCI_EN is set via the SMI path
  (SMI_CMD 0xB2, ACPI_ENABLE 0xF1) — no hardcoded SLP_TYP
  anywhere; the value is parsed from the table. A
  temporary `pwdbg` raw-write command proved the
  register-level behaviour and was REMOVED before the
  deliverable test ran (grep-verified: zero `pwdbg` /
  `acpi_dbg` references in the tree).
- `diag acpi` (flat `acpi` command) is a permanent
  diagnostic: RSDP/RSDT/FADT addresses, PM1a/PM1b,
  SLP_TYP values, live PM1a_CNT.
- `shutdown` failure path as built: `acpi_poweroff()`
  returns -1 only before the write (no tables, bad
  checksum, no _S5_, SCI_EN enable failure) → shell
  prints "shutdown: ACPI poweroff unavailable, system
  halted." and halts. After the write, `acpi_poweroff()`
  itself halts (a returned write means the hardware did
  not power off; there is nothing else to try).
- VERIFIED 2026-10-30: `tests/qemu_test_core_power.py`
  + setup, 21 checks, first-run PASS on the build with
  the fix (diag PM1a 0x604; usage errors; confirm-abort
  for `n` and for non-y; reboot restarts at once;
  shutdown+y and poweroff --force each exit QEMU;
  halt --force prints "System halted." with QEMU still
  running and no new prompt; alice refused on all three
  power commands with root-only messages).

## 3. Family (c) — User management, completed (session/fs)

New kernel APIs (kernel/users.c + new kernel/groups.c):
- users_add(name, password): root-gated by the caller. Name
  rules: 1-31 chars, no ':' / space / newline (names travel
  through the shell tokenizer and the colon file format).
  uid: max existing uid + 1, minimum 1000 for a new account
  (uid 0 is root, never assigned); MAX_USERS 8 cap. Salt from
  the existing CSPRNG generator; hash via users_hash. Rewrite
  uses the existing passwd_file_buf pattern (file-scope,
  root-owned 0600, reload + verify the new password checks
  before reporting success). Setup-mode rule: if no users.txt
  exists, useradd creates it with just the new user (after
  that, setup mode ends and logins use the file — documented
  in the command help).
- users_delete(name): root-gated by the caller. Refuses uid 0
  and unknown names. Rewrites users.txt without the user,
  reloads, verifies the user is gone. The shell ALSO refuses
  deleting the current session user and drops the deleted
  user's fails.txt record (shell-local fails_drop helper —
  otherwise a re-added name would inherit a lockout).
- groups.txt: `name:gid:member1,member2` lines, MAX_GROUPS 8,
  max 8 members per group, gid min 1000, root-owned 0600,
  same load/rewrite discipline as users.txt. Commands:
  groupadd, groupdel, groupmod <group> add|remove <user>
  (both names must exist; add of an existing member / remove
  of a non-member prints a message, not a silent success).
- groups [user] — group names for the user (default: session
  user). id [user] — `uid=<n> groups=<g1,g2>` or
  `groups=none`. Unknown user → "no such user" refusal.
- fs_stat_as(name, uid, &owner, &mode, &size) (fs/nxtsfs.c +
  fs/vfs.h): allowed iff uid==0, caller owns the file, or
  caller can read it (metadata disclosure follows the read
  rule). Powers `stat` and the editor save path.
- fs_chown_as(name, new_uid, caller_uid) (same files):
  caller MUST be root (enforced in the fs layer as well as
  the shell handler); metadata-only owner change + save_dir,
  mirroring fs_chmod_as. Powers `fs chown <file> <user>`
  (root only, username resolved via new users_uid helper).
- passwd and unlock are UNCHANGED (already complete).

GROUPS + FILE PERMISSIONS — honest limit, decided here:
nxtsFS directory entries carry NO group field (see §0), so
group-based file permission enforcement would require an
on-disk format change and a disk migration. Groups in this
run are therefore managed account membership + display
(id/groups), and file access stays uid-based (owner vs
other). Group-enforced file permissions are RECORDED AS
REMAINING WORK (future format change), not half-implemented
by overloading the flags field. This is a deliberate scope
decision, not a gap discovered later.

Security: root gating in the HANDLER (shell checks
session_uid before calling; the fs layer re-checks for
chown). Passwords: echo off (existing read_line), buffers
cleared after use (existing passwd pattern, reused for
useradd prompts), never printed, never logged (audit lines
carry usernames + event names only, never passwords or
hashes). No hash/salt/password material in test fixtures
beyond the mkuser-generated users.txt the existing tests
already use (fixed salts, test-only passwords, never real
credentials).

Test plan: QEMU test with a seeded users.txt (root + alice):
root useradd carol (prompts, then login as carol works);
root userdel carol (login as carol then fails); userdel root
refused; userdel of the session user refused; non-root
useradd/userdel/groupadd refused with "root only" and no
file change (verified by cat users.txt); groupadd/groupmod/
groups/id round-trip; passwd for a new user works; chown
round-trip (root changes owner, non-owner loses write);
stat shows owner/mode/size. Negative: bad names (empty,
overlong, colon) refused; 9th user refused (MAX_USERS);
unknown user/group refused everywhere.

## 4. Family (d) — Nano-like terminal editor (fs)

Command: `fs edit <file>`. No external dependencies; works
in the kernel console (VGA text and framebuffer text modes).

New console APIs (kernel/console.c + console.h), buffer-only
(no serial spam — serial would receive a full redraw per
keystroke):
- console_set_cursor(row, col) — clamped to 80x25, updates
  the hardware/VGA cursor or the fb cursor cell.
- console_put_at(row, col, ch) — writes text_buf only.
- console_present() — renders text_buf (render_fb/render_vga).
- console_rows()/console_cols() — 25/80.

New keyboard codes (drivers/keyboard.c + keyboard.h):
E0 arrows → KEY_UP 0x103, KEY_DOWN 0x104, KEY_LEFT 0x105,
KEY_RIGHT 0x106; E0 Home/End → KEY_HOME 0x107, KEY_END
0x108; E0 Delete → KEY_DEL 0x109 (existing PgUp/PgDn keep
0x101/0x102). Release codes (scancode|0x80, E0 or not)
continue to be ignored, so arrow releases never move the
cursor. Ctrl tracking: left Ctrl make 0x1D / release 0x9D
and E0 right-Ctrl make/release set a ctrl flag; a letter
with ctrl down is delivered as its control code (a→1 ...
z→26), so ^O=15, ^X=24, ^W=23, ^K=11, ^U=21, ^G=7.
shell read_line gains a guard: control codes (<32, except
\n and \b) are ignored, so Ctrl keys can never pollute a
login/password/line buffer. shell_loop already ignores
c<32, so the shell prompt is unaffected.

Editor (new kernel/editor.c, file-scope state only):
- Buffer: 32 KiB file-scope static + NUL. Load via
  fs_read_range_as windows with the session uid (permission
  enforced). Missing file → empty buffer, filename set,
  nothing created until save. File over 32 KiB → clean
  refusal ("edit: file too large (max 32768 bytes)"), no
  partial edit. Tabs are expanded to 4 spaces on load
  (documented: the editor has no tab-stop model, so it
  normalises rather than corrupting columns).
- Screen: rows 0-22 text (23 lines), row 23 status
  (filename, `*` when modified, cursor line/col), row 24
  key hints (^O Save ^X Exit ^W Search ^K Cut ^U Paste
  ^G Help). Cursor movement: arrows, Home/End, PgUp/PgDn
  (23-line pages), clamped; the window scrolls to keep the
  cursor visible.
- Editing: printable insert, Enter splits a line, Backspace
  deletes (joins lines at line start), Del deletes forward
  (joins at line end). Modified flag on any mutation.
- ^O save: status-row prompt "File to write: <current>";
  Enter keeps the current name (save), typing a new name
  saves as that file (save-as). Write via fs_write_as with
  the session uid; existing files keep their mode (from
  fs_stat_as); if the save changed ownership (root editing
  another user's file — fs_write_as resets uid to the
  caller), ownership is restored via fs_chown_as. Serial
  marker "EDIT-SAVED <file>" (serial_write, screen
  untouched) so tests can observe a save mid-session.
- ^X exit: if unmodified, exit at once. If modified,
  status-row prompt "Save changes? (y/n/c)": y saves then
  exits, n discards and exits, anything else cancels.
  Exit prints "edit: done" via console (serial-visible)
  and clears the screen; the shell prompt redraws normally.
- ^W search: status-row prompt "Search: "; finds the next
  occurrence after the cursor, wrapping once; moves the
  cursor there; "Not found" on the status row otherwise.
- ^K cut: deletes the cursor line into a 1024-byte cut
  buffer (longer lines refuse the cut with a message,
  never truncate silently). ^U paste: inserts the cut
  text at the cursor followed by a newline.
- ^G: shows a help overlay (same screen rows, any key
  returns to editing) listing every key binding.
- Limits, stated honestly: 32 KiB file cap; no syntax
  highlighting; no undo (deliberate — an undo tree is a
  second editor, not a missing key); no multi-file buffers.

Test plan: QEMU test (seeded disk, root): create + type +
^O + ^X, then `cat` proves content; open + arrow/Home/End/
search/cut/paste round-trip, then `cat` proves the result;
unsaved-change prompt: ^X then "n" discards (cat proves
old content), ^X then "y" saves; save-as writes the new
file and leaves the old untouched; oversized file refused;
permission refusal (non-root editing a 0600 root file
fails before the editor opens); help overlay opens and
returns. All proofs via post-exit `cat`, never via screen
scraping (the serial log cannot see the screen).

## 5. Family (e) — Firewall (net)

New net/fw.c + net/fw.h. Rule table: MAX_RULES 16, ordered,
first match wins; no match → default policy.
- Rule fields: direction (in/out), action (allow/deny),
  proto (any/icmp/tcp/udp), src (any or dotted IP),
  sport (any / single / lo-hi range), dst (any or dotted
  IP), dport (any / single / lo-hi range).
- State: enabled flag (default off → no filtering at all),
  default policy (default allow), drop counter.
- Hook points (net/net.c, additive): net_rx_frame — after
  src/dst/proto are parsed and dst validated, before ICMP/
  UDP/TCP dispatch; L4 ports parsed from the L4 header when
  proto is TCP/UDP and the header is present, else 0.
  net_ip_send — before the packet is built; payload is the
  L4 segment, ports at +0/+2 for TCP/UDP when present.
  A deny drops the packet and bumps the fw drop counter
  (visible via `fw stat`); it never logs packet contents.
- Persistence: fw.txt, root-owned 0600, lines
  `in deny tcp any any any 80` (dir action proto src sport
  dst dport; ports `any`, `80`, `8000-8100`). Loaded lazily
  on first fw use (net_init runs before fs_mount, so boot
  load is impossible — documented). Malformed lines are
  skipped, never fatal (fails.txt precedent). Save on every
  mutating command; enabled/default persist in the same
  file as `#enabled 1` / `#default deny` header lines?
  DECISION: two header lines, `#fw enabled=1` and
  `#fw default=deny`, parsed like rules but stored first;
  a file without headers means disabled + default allow.
- Commands (net group, root-gated mutations, read-only
  list/status/stat for anyone):
  fw status | fw enable | fw disable |
  fw default allow|deny | fw list | fw add <in|out>
  <allow|deny> <any|icmp|tcp|udp> <src> <sport> <dst>
  <dport> | fw del <n> | fw clear | fw stat
  (`fw` bare prints usage; `fw add` validates every field
  — bad direction/action/proto/IP/port/range → usage error,
  never a half-added rule; `fw del` takes the 1-based list
  number from `fw list`, out-of-range refused.)
- Security notes: with default deny, the operator must
  allow DHCP (UDP 67/68), DNS (UDP 53) and ICMP explicitly
  or the machine loses network — the help text says so.
  Rules never match on payload contents (headers only).
  The repo/castore fetch paths are ordinary outbound TCP
  and ARE subject to outbound rules (documented: an
  outbound deny-all breaks pkg update — that is the
  firewall doing its job, not a bug).

Test plan: QEMU test with a raw-packet peer (socket netdev
peer sending crafted Ethernet/IP/UDP + ICMP frames, in the
style of the existing peer harnesses): default-allow +
deny-UDP-port rule → datagram to the denied port produces
no reply and fw stat drops increase, while ping still
replies; deny-ICMP rule → ping gets no reply; outbound
deny rule → guest ping gets no reply (packet never sent);
rule persistence: add rules, reboot (shell `reboot`), list
shows the same rules; malformed fw.txt lines skipped;
non-root fw add/del/enable refused with "root only" and
no file change. Host test for the pure matcher if it
compiles cleanly against the host_http pattern (matcher
has no fs/console deps by construction); otherwise the
QEMU proof stands alone and is recorded as such.

## 6. Family (f) — Remaining CLI gaps + the flat-name decision

- `system date` — CMOS RTC (regs 0x00/0x02/0x04/0x07/0x08/
  0x09 + status B for BCD/24h handling, update-in-progress
  wait bounded): prints `YYYY-MM-DD HH:MM:SS` (year =
  2000 + 2-digit register, the QEMU/SeaBIOS convention —
  documented). No `date set` in this run (setting the RTC
  is a clock-discipline change, recorded as remaining).
- `fs stat <file>` — size, owner (uid + name where known),
  mode (octal), sector count, via fs_stat_as.
- FLAT SHELL-NAME DECISION (final, no half-measure): KEEP
  flat names as aliases. Reasons, recorded: (1) the grouped
  dispatch already exists, so both forms work and help is
  already grouped; (2) ~40 QEMU harnesses invoke flat names
  — removing them means rewriting and re-verifying every
  harness in the same run, which would crowd out the five
  feature families the user actually ordered; (3) no
  explicit user order to remove them exists (the standing
  note says removal needs a user order + harness updates).
  The help index keeps saying "Flat names still work."
  Revisit only on an explicit user order.
- `reboot` carried exception: see §2.
- Group-enforced file permissions: recorded as remaining
  (see §3). RTC set, editor undo, editor >32 KiB files,
  top job control, HTTP proxy/server: recorded as
  remaining, NOT half-implemented.

## 7. Security + privacy checklist (applies to every family)

- Privileged operations root-gated in their handlers
  (shell checks session_uid; fs layer re-checks for
  chown; fw mutations root-only; shutdown/halt root-only).
- Passwords: echo off, buffers cleared, never printed,
  never logged, never stored in clear (salted hash only).
- No sensitive data in serial logs or fixtures: audit
  lines carry event + username only; fw drops count
  packets, never contents; test passwords are fixed
  test-only values via mkuser (existing pattern).
- Adversarial + boundary + negative tests per family:
  malformed input, privilege-escalation attempts (non-root
  tries every privileged op), boundary values (MAX_USERS,
  MAX_RULES, 32 KiB cap, port ranges, name lengths),
  oversized inputs (refused, never truncated silently),
  failure-closed behaviour (ambiguous = FAIL).
- Carried weaknesses (unchanged, not hidden): password
  hash is not a production KDF; early-boot CSPRNG limits;
  no constant-time crypto; predictable TCP ISNs; fs commit
  not atomic; dhcp/dnsset still lack a uid gate
  (pre-existing — gating them is a separate behaviour
  change, recorded as remaining, NOT snuck into this run).

## 8. Test + neighbour plan

- One QEMU test per family: core_hw (cpu/pci/disk/sysinfo/
  uptime/ps/top), core_power (shutdown/halt/reboot rules),
  core_users (user/group/chown/stat + negatives), core_edit
  (editor round-trips + prompts + limits), core_fw (rules,
  drops, persistence, negatives). Each with a *_setup.py
  where a seeded disk is needed, following the existing
  harness pattern (ISO + workdir args, monitor sendkey,
  serial-log waits, QEMU always terminated, exit 0 only
  when every check passes).
- Host tests where the logic is host-testable (fw matcher
  if it compiles cleanly; otherwise QEMU-only, recorded).
- Neighbours on the final ISO, all must PASS: TLS suites
  (incl. tls13 14/14), castore 10/10, legacy 19/19, http
  23/23, desktop neighbours, shell_groups, plus the
  pre-existing core suites (storage, chmod, cp, users
  paths) that touch changed code (keyboard, console, fs,
  shell dispatch).
- Changed-code blast radius, for neighbour selection:
  keyboard.c (arrows/Ctrl — every typing test), console.c
  (new APIs only, no existing path changed), shell.c
  (read_line guard + new commands), fs/nxtsfs.c (stat/
  chown are additive; write path untouched), net/net.c
  (two hook calls, no-ops when fw disabled), users.c
  (additive APIs), build.sh (file lists only).

## 9. Completion status (filled at wrap-up, not in advance)

- (a) hardware/resources: COMPLETE + deliverable-tested
  2026-10-30: kernel/hwinfo.c (CPUID vendor/brand/family/
  model/stepping/flags, bus 0 PCI scan, ATA + fs sectors)
  + shell cpu/pci/disk/uptime/sysinfo/ps/top (diag +
  proc groups, flat + grouped dispatch). tests/
  qemu_test_core_hw.py (+ setup) 34 checks PASS first
  run: cpu vendor/brand/family/model/stepping, pci host
  bridge + VGA + BAR0, disk 32768 sectors total (16 MiB),
  mem/ticks/uptime formats, sysinfo sections + version,
  ps session + no jobs, top refreshes advancing uptime +
  clean q on quit, grouped forms, help diag/cpu entries,
  and a no-drive boot proving the ATA-present-but-
  unmounted messages. (The 2026-10-29 smoke scripts in
  /tmp are superseded by this test and were cleaned up.)
- (b) shutdown/power: COMPLETE + deliverable-tested
  2026-10-30: kernel/acpi.c + shell shutdown/poweroff/halt
  + `acpi` diagnostic; tests/qemu_test_core_power.py (+
  setup) 21 checks PASS first run, incl. real QEMU
  poweroff on shutdown+y and poweroff --force, halt
  semantics, confirm fail-closed, non-root refusals,
  reboot unchanged. FADT offset bug found + fixed in-run
  (see §2 implementation note).
- (c) user management: COMPLETE + deliverable-tested
  2026-10-30: kernel/users.c users_add/users_delete/
  users_uid/users_valid_name + new kernel/groups.c +
  fs_stat_as/fs_chown_as (+ groups.txt joins the
  system-file list) + shell useradd/userdel/groupadd/
  groupdel/groupmod/groups/id/chown/stat; passwd/unlock
  unchanged. tests/qemu_test_core_users.py (+ setup)
  82 checks PASS (second run; first run caught 3 test
  bugs only — groups endswith assertions + a sendkey-
  doubling desync in the password helper — kernel
  behaviour was correct throughout; helpers hardened
  with wait_either guards, bare-Enter resync, and
  id-verified useradd). Coverage incl. setup-mode
  useradd + login transition, passwd for an added user,
  uid-0 named session (admin) cannot delete itself,
  3-failure lockout + fails-record drop on delete +
  re-added user not locked out, MAX_USERS cap at 8,
  chown/stat permission rules, all non-root refusals.
- (d) editor: COMPLETE + deliverable-tested 2026-10-30:
  console_set_cursor/put_at/present/rows/cols + E0
  arrows/Home/End/Del + Ctrl-letter codes in the keyboard
  driver + read_line control-code guard + new kernel/
  editor.c (32 KiB buffer, 23-line screen, status + hint
  rows, ^O save/save-as with owner+mode preservation via
  fs_stat_as/fs_chown_as, ^X y/n/c prompt, ^W search with
  wrap, ^K cut (1024-byte cap) / ^U paste, ^G help, tab
  expansion, EDIT-SAVED serial marker). tests/
  qemu_test_core_edit.py (+ setup) 59 checks PASS
  (second full run; the first full run caught 3 test
  bugs only — a stale-prompt seg bug in sh(), a fixture
  uid error seeding tab.txt/long.txt as 1001 instead of
  alice's 1000, and a Boot C stat expectation of 1001
  instead of 1000 — kernel behaviour was correct
  throughout; a final single-check flake on the y-save
  path was a QEMU sendkey doubling cancelling the y/n/c
  prompt, fixed test-side with a Backspace-recovery
  retry in edexit_answer). Coverage incl. create/type/
  save/exit, Home/End/insert, search cursor move, cut/
  paste reorder, backspace-join + del-join, n-discards /
  y-saves / c-cancels, save-as, help overlay, search-
  miss, tab expansion, oversized refusal, overlong-cut
  refusal, root-only refusal, root-save owner+mode
  preservation. No kernel change was needed for the
  test failures; the editor code is unchanged since its
  smoke verification. POST-COMPLETION HARDENING
  2026-10-30 (run reopened after two later full runs on
  the final ISO failed Boot A content checks): the
  failures form ONE cascade each (root = one
  wrong-content step, e.g. home/end insert; all chained
  new.txt steps downstream inherit the wrong base),
  while mechanics markers always pass and 3/3 focused
  Boot-A-prefix repros (dumped cat output) show exact
  content — transient editor-input loss under load, not
  a kernel bug (the editor echoes nothing to serial, so
  edtype/edkey send blindly). Test-only fixes, zero
  kernel change: edtype delay 0.15s -> 0.30s; Boot A
  retries once from a fresh disk (attempt 1 quiet, only
  the final attempt's lines print + NOTE; all content
  assertions stay exact); sh() echo match
  whitespace-normalized (a doubled SPACE is semantically
  benign — the shell tokenizes whitespace runs
  identically — but broke exact echo matching, proven
  by a Boot C failure where 'write  own.txt' executed
  fine yet the exact check timed out waiting for a
  second prompt that never comes). Hardened re-run:
  59/59 PASS, exit 0, no retry triggered. A VM
  replacement during this investigation wiped /tmp +
  tools again (workspace + ISO intact); toolchain
  restored from cache without a lock fight; /tmp inputs
  recreated.
- (e) firewall: COMPLETE + deliverable-tested 2026-10-30:
  new net/fw.c + net/fw.h (MAX_RULES 16, ordered, first
  match wins, default policy, drop counter, fw.txt
  persistence with #fw headers, lazy load, silent skip of
  malformed lines) + hooks in net_rx_frame (after dst
  validation, before dispatch) + net_ip_send (before build
  and before ARP) + fw.txt joins the system-file list +
  shell fw status/enable/disable/default/list/add/del/
  clear/stat (net group, mutations root-gated in the
  handler, bare fw prints usage, every add field
  validated). tests/qemu_test_core_fw.py (+ setup) 71
  checks PASS (third full run; the first two runs caught
  test bugs only — a stale-prompt seg bug, then a
  sendkey-doubling desync fixed by a verify-before-Enter
  sender — plus one REAL kernel-side parser bug found by
  the malformed-file test: fw_split capped at 7 words
  instead of rejecting 8-word lines, fixed to return -1
  on overflow). Coverage incl. inbound ICMP deny (no
  guest reply + drops up) vs allow (reply arrives),
  inbound UDP deny vs allow (drops up vs unchanged),
  outbound ICMP deny (ping no reply + peer sees no
  request + drops up) vs allow, bad direction/port/
  range/word-count/del-number refusals, default deny vs
  allow, range + dst-IP matching (8005 denied, 8101
  untouched), clear/disable, rules + enabled state
  persisting across a shell reboot, malformed fw.txt
  (headers + 1 good rule kept, 3 bad lines skipped),
  alice refused on all 5 mutations while list/status
  stay readable + admin proves nothing changed. ARP is
  deliberately unfiltered (resolution layer). Kernel
  behaviour was correct throughout the test debugging.
- (f) gaps + flat-name decision: COMPLETE 2026-10-30:
  `date` wired to the existing hw_rtc_read (system group,
  flat + `system date` dispatch, dedicated help entry,
  YYYY-MM-DD HH:MM:SS with hand padding — the minimal
  printf has no %02u; year = 2000 + RTC year register;
  no `date set` in this run, recorded as remaining).
  `stat` was DONE in (c). FLAT-NAME DECISION (final):
  KEEP flat names as aliases — grouped dispatch already
  exists, ~40 harnesses invoke flat names, and no
  explicit user order to remove them exists; the help
  index keeps saying "Flat names still work." Revisit
  only on an explicit user order. Covered by tests/
  qemu_test_core_hw.py (date format + ranges, flat +
  grouped forms, help date entry).
- Neighbours on the final ISO b3a49119… (5,517,312 B), runner
  ~/workspace/nb-work/run-core-neighbours.sh, main run 2026-10-30
  02:02–03:52 PKT (31 suites) + supplementary re-runs the same
  night: PASS (27 in the main run + 4 supplementary):
  core_power, core_edit, core_fw, core_hw, tls13 14/14, tls,
  tls_ecdhe, tls_chain, tls_anchor, tls_anchor_stop, tls_ske,
  tls_peer, tls_hostmatch, tls_alpn, tls13_wrappedcert,
  castore, legacy 19/19, http, http_sec, desktop, desktop10,
  desktop_apps, desktop_newapps, desktop_web, shell_groups,
  chmod, cp. Supplementary PASS: storage (after a test-only
  marker fix, see below), tls13_tampered (guest refused
  tampered Finished, no panic), tls13_tamperedcv (all 6
  tampered-CV cases refused at stage 3, no panic),
  core_users full suite (clean re-run, exit 0, zero
  failures). Main-run FAILs, all diagnosed NON-KERNEL:
  (1) core_users single check "fails record dropped on
  delete" — harness flake, proven: fails_drop is correct
  by code reading, fs_write_as len-0 DOES truncate (need
  forced to 1 zeroed sector, size set to 0), and the check
  passed in 6 of 7 runs of that path (original run, two
  clean full re-runs, two focused C1+C2 repros with the
  C2 serial log dumped — cat output lines EMPTY after
  delete in both repros) vs 1 runner-run failure; the
  (c) test's cmd() predates the echo-aware/verified
  sender and its drop check is a fragile negative
  substring on a raw serial span. (2) tls13_tampered +
  tls13_tamperedcv exit=1 "missing fixture
  rsa-leaf-cert.pem" — runner bug (mine): the runner
  omitted qemu_test_tls13_setup.py for those two suites
  (fixed in run-core-neighbours.sh after the run; the
  supplementary runs WITH setup both PASS). (3) storage
  RESULT: FAIL on marker "Hello from nxtsFS" — stale
  test expectation: that string appears nowhere in the
  current kernel (mount prints "Filesystem mounted" +
  "Filesystem: nxtsFS v1, …"); the fs behaviour itself
  was correct in the failing log (persist.txt written,
  read back after reboot, ls correct). Test-only fix:
  marker replaced with "Filesystem: nxtsFS v1" (present
  twice in the log); supplementary re-run PASS, all
  markers FOUND. No kernel code changed for any of the
  four main-run FAILs. Incidents during neighbours: a VM
  replacement wiped /usr/bin tools mid-run (workspace +
  final ISO intact); cache libs reinstalled via dpkg -i
  and the runtime replay restored QEMU 8.2.2 / xorriso
  1.5.6 / GRUB on its own (dpkg lock held by pid 3347 —
  waited out, not fought); the first runner (pid 36115)
  died in the replacement and was restarted detached
  (setsid/nohup).
- Remaining scope (explicit): (1) group-enforced file
  permissions (needs an on-disk nxtsFS format change +
  disk migration — groups in this run are membership +
  display only, by design); (2) `date set` (RTC setting
  is a clock-discipline change, not wired); (3) editor
  undo; (4) editor files over 32 KiB; (5) top job
  control (kill/renice from the monitor); (6) HTTP
  proxy/server; (7) test-hardening: port
  tests/qemu_test_core_users.py cmd() to the
  echo-aware/verified sender pattern (proven by the fw
  test) and make its drop check line-based instead of a
  raw-span negative substring — the kernel behaviour is
  proven correct, the harness is the flake source;
  (8) Bochs re-run for v1.1.x trees; (9) live Vercel
  guest fetch from the kernel; (10) real hardware
  testing; (11) user-side Virt-Manager retests (repo
  commands, desktop fixes, Phases 2–4, core CLI
  features). NO release in this run (per brief): tree
  left uncommitted on main over 23e024c (v1.1.4),
  VERSION 1.1.4, no tag, no push, no Drive upload.
