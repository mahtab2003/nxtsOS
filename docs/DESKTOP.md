# nxtsOS desktop — Phase 10 (v0.10.0)

The desktop shell (`desktop` at the shell prompt) is the graphical
environment. This document describes what v0.10.0 adds on top of
the v0.8.0 desktop (icons, Start launcher, taskbar, notifications,
quick settings, lock screen, Settings window, Files window, About
window, Calculator package). All Phase 10 settings persist in
`settings.txt` on disk alongside the v0.8.0 keys.

## Appearance (Settings → Appearance page)

The Settings window has two pages. Page 1 is the original four
rows (idle timeout, mouse speed, clock format, desktop icons) at
unchanged positions. The Appearance button switches to page 2:

- **Theme**: Classic (the v0.8.0 look, exactly), Dark, Light,
  High-contrast. The theme recolours the desktop background,
  taskbar, panels and panel text. Window *client areas* stay
  light grey with black text in every theme — a deliberate
  choice so all window content stays readable without
  refactoring every content painter.
- **Accent colour**: Blue (default, the old focused-title
  colour), Gold, Green, Red. Applied to the focused window's
  title bar.
- **Wallpaper**: Solid, Gradient (theme background lerped
  toward black in 4-pixel bands), Dots (accent dots every
  48 pixels).
- **Low-resource mode**: forces the solid wallpaper and
  raises the pending-redraw throttle from 2 ticks to 5.
- **Large text**: desktop icon labels drawn at 2× size.
- **Shortcuts**: three key presets — {Lock L, Workspace W},
  {Lock K, Workspace J}, {Lock X, Workspace Z}. Shortcuts
  (and snap keys) fire only when no text input has focus.
  The key dispatch order is: the lock-screen password
  input first (while locked, keys go to the password
  buffer, never to shortcuts); then the Settings Unlock
  field, which is checked before the Settings search
  field, so typing an account name cannot leak into the
  search box; then the Settings search field; then the
  focused window's inputs, in branch order — Editor
  filename field, else the Editor body itself (the body
  consumes every printable key, so a focused Editor
  blocks shortcuts even with no field focused), Web
  Save-as field before the Web address field, Files
  chmod-mode field before the Files rename field, Repo
  URL field, Network DNS field, Network ping field;
  then a focused GUI-app (user) window, whose keys are
  queued to the app. Only if none of those consumes the
  key do the desktop-global shortcut and snap keys fire
  — so a focused built-in window with no field focused
  (Monitor, Settings with neither field focused) does
  not block shortcuts.
  CORRECTION: an earlier wording listed only "lock
  screen, Settings search, Editor, Web address field,
  and focused user windows" as taking priority, in
  that order; that list omitted the Settings Unlock
  field (which outranks the search field), the Web
  Save-as field, and the Files, Repo, and Network
  fields, all of which consume shortcut letters while
  focused.

Out-of-range values in `settings.txt` are ignored with a
serial marker (`settings: ignored invalid theme=99`);
non-numeric values are skipped. A corrupt settings file
cannot break the desktop — it starts with defaults.

New `settings.txt` keys (all optional, defaults shown):
`theme=0 accent=0 wallpaper=0 lowres=0 bigtext=0 shortcuts=0`.

Below the four page-1 rows, a fixed "Unlock user:" row is
the desktop form of shell `unlock <user>`: click the field,
type the account name, click Unlock. It clears that
account's brute-force failure counter through the shell's
own unlock primitive, in the shell's order (an empty field
only reports "unlock needs user", then the root check,
then the existence check) — root-only, because the
primitive itself has no uid rule and a non-root unlock
path would let any session reset another account's
counter and defeat the 3-failure lockout (the Repo
Update/Install precedent: the handler check is the only
barrier). A name that is not an account reports
"settings: no such user <name>" instead of a false
success, and writes no audit entry for it — the shell's
`unlock` refuses the same way, through the same
primitive. A success prints "settings: unlocked <name>"
and clears the field; a refusal keeps it for a retry. No confirm: unlocking only resets a counter. The
row sits at a fixed position (below the rows, above the
Appearance toggle) so it never moves when the search
filters the rows, and it is not drawn on the Appearance
page; no window resize, so the toggle, Save, and every
earlier row keep their positions. Until now a root
administrator working entirely in the desktop had no way
to unlock a locked account and had to drop to the shell
for `unlock`, even though the lockout itself is what
stops a desktop session from brute-forcing a password.

## Workspaces and window snapping

- Two workspaces (WS1/WS2). The taskbar WS button toggles
  between them. Windows belong to the workspace they were
  opened on; other-workspace windows are hidden from the
  desktop, the taskbar buttons, and click detection.
- Snap keys (when no text input has focus): `[` snaps the
  topmost non-minimised window of the current workspace to
  the left half, `]` to the right half, `\` maximises a
  plain window and restores a maximised one — and restores
  a half-snapped window to the geometry the first snap
  saved, so `\` after `[` is a restore, not a second
  maximise (the desktop10 test proves exactly that step:
  `[` snaps, `\` restores to the pre-snap geometry). The
  first snap saves the window's geometry for restore, and
  a later half-snap does not overwrite it, so restore
  always returns to the pre-snap geometry.
  CORRECTION: an earlier wording said `\` "toggles
  maximise/restore", which left the half-snapped case
  unstated; a snapped window restores under `\`, it
  does not maximise.

## Built-in applications (Start launcher, column 2)

- **Editor**: text editor for files up to 8192 bytes.
  Larger or missing files are refused, never truncated
  silently (`editor: refused <name> (missing or over 8192
  bytes)`). Bytes below 32 (except newline) and at/above
  127 are sanitised to `?` on load, with a marker
  (`editor: sanitized N bytes in <name>`). Filename row
  to focus, body to edit, `[`/`]` move the cursor, Save
  writes back (mode 0644).
- **Monitor**: uptime, memory total/free, window count,
  network RX/TX/drops and IP, refreshed every 100 ticks.
  Below the IP line it lists live background jobs (the
  desktop form of shell `jobs`, same table through
  `proc_bg_at`, up to 4 rows) and a [Kill] button: the
  desktop form of shell `kill <pid>` through the same
  `proc_bg_kill` with the session uid, so root kills any
  job and anyone else only their own. Select a row, then
  Kill twice to confirm (armed by pid, not by row, so a
  job finishing between the clicks cannot make the
  confirm kill a different job that slid into the row).
  Kill with no selection only reports it; a failed kill
  keeps the selection for a retry, a success clears it.
  Below the Kill button it lists disk space through the
  shell's `fs` rule (total and free sectors, redrawn every
  second with the rest of the window; "(not mounted)" with
  no disk) — until now a desktop-only user had no way to
  see disk space at all, and a full disk is exactly what
  blocks a package install or an Editor save. The window
  is 480×440 for the two Disk rows; no earlier row or
  click coordinate moved for them.
- **Network**: MAC, DHCP state, IP/mask/gateway/DNS,
  RX/TX counters, with [Run DHCP] and [Ping gateway]
  buttons. With no NIC, opening the window reports
  `network: no device` (and draws "No network device
  found."): [Run DHCP] reports "No network device",
  while [Ping gateway] reports "Not configured, run
  DHCP first" — with no NIC the IP is never
  configured, so its configured check fires, not a
  no-device check — and neither button hangs.
  CORRECTION: the old wording said both buttons
  report "no device"; only Run DHCP does, Ping
  gateway reports not-configured.
  Below the message line, a DNS field and [Set DNS] set
  the resolver address through the shell's `dnsset <ip>`
  rule (the shell command has no uid check, so neither
  does this): an empty field only reports "DNS needs
  IP", a malformed address fails with its own reason
  and keeps the field for a retry, and a success reloads
  the DNS line in place and clears the field. The DNS
  line itself is drawn only once the window is
  configured (the IP/mask/gateway/DNS rows appear
  only after DHCP), so a Set DNS before DHCP stores
  the value but shows no line until then — and a
  later DHCP run overwrites it with the offered DNS.
  The field caps at 63 characters like the Web and
  Files fields.
  Click the field, type the dotted-quad address, click
  Set DNS. No confirm: setting a DNS address is
  non-destructive and reversible by setting another,
  Repo Set precedent.
  Below the Set-DNS row, a Ping row (the window is
  480×400 for it) pings an arbitrary host through the
  shell's `ping <ip>` rule — Ping gateway only probes
  the gateway, so a desktop-only user checking a repo
  host or LAN peer had no desktop probe until now.
  Click the Ping field, type the dotted-quad address,
  click Ping: an empty field only reports "Ping needs
  IP", a malformed address fails with its own reason
  and keeps the field for a retry, an unconfigured IP
  reports "not configured" instead of probing (the
  configured check fires before the parse, so an
  unconfigured window reports "not configured" even
  for a malformed address), a reply clears the field,
  and a timeout keeps it for a retry.
  The Ping field is separate from the DNS field, so
  typing a host address never touches the DNS field.
  No confirm: a ping is a read-only probe.
- **Web**: text-only HTTP/HTTPS browser. One address
  field (`host[:port][/path]`, optional `http(s)://`
  prefix; HTTPS uses TLS port 443). Fetch blocks the
  desktop loop while it runs. The body buffer is 8192
  bytes: larger pages are truncated, not failed, and the
  truncation is reported (`web: truncated at 8192`, and
  the status line "8192 bytes (buffer full, may be
  truncated)"). Certificate failure reports
  `web: certificate refused`. Up/Down scroll the body.
  Below the body, a "Save as:" row (the window is
  520×400 for it) saves the fetched body to disk
  through the filesystem's own write rule (session uid,
  mode 0644, Editor Save precedent) — until now a
  desktop user who fetched a page had no way to keep
  it at all, and the shell's `http`/`https` commands
  only print to the console. Click the Save field,
  type a filename, click Save: with no fetch yet it
  only reports "save needs fetch", with an empty name
  only "save needs name", and an existing file is
  refused ("save exists"), never overwritten — the
  write primitive itself overwrites, so the refusal is
  what protects an existing file. A success prints
  "web: saved <name> <n> bytes" and clears the field;
  a failure keeps it for a retry. The "no fetch yet"
  case is really the length check: a fetch that
  returned a 0-byte body also leaves the length at 0,
  so Save reports "save needs fetch" for it too.
  A truncated page saves the truncated body as shown,
  not 8192 bytes: the 8192-byte fetch buffer holds
  headers plus body while fetching, and the saved
  length is the body length after the headers are
  stripped (at most 8191 bytes minus the headers), so
  the status line's "8192 bytes (buffer full, may be
  truncated)" is the buffer-full label, not a byte
  count. CORRECTION: an earlier wording said a
  truncated page "saves the 8192-byte buffer as
  shown"; that count was wrong for the reason above.
  No confirm:
  saving writes a new file and overwrites nothing.
  This is a text viewer, not a browser engine: no HTML
  rendering, no images, no JavaScript.
- **Viewer**: BMP image viewer. Only 24-bit uncompressed
  BMPs, at most 128×128 pixels, file at most 128 KiB.
  Anything else is refused with a specific reason
  (not a BMP / only 24-bit uncompressed / oversize /
  truncated pixel data / missing or over 128 KiB).
  Pixels are drawn 1:1, BGR converted to RGB.
- **Console**: the `term.nxpkg` package (see below), a
  local echo console. It is NOT the text shell and
  cannot run programs; it has help/echo/clear/about/
  exit built-ins.
- **Packages**: lists the installed packages (name +
  version) from the registry. Click a row to select it
  (highlighted, `packages: selected <name>`), then
  [Remove] uninstalls it through the shell's
  `pkg remove <name>` rule without force: root-only
  (a non-root session reports "remove needs root"),
  dependents refuse without force, and the removal
  needs a two-click confirm (Files Delete pattern) —
  the first click only reports "remove confirm
  <name>". Remove with no selection only reports
  "remove needs selection"; a failed removal keeps
  the selection for a retry, a success clears it
  and the list redraws from the live registry.
  [Rollback] undoes the last system update through
  the shell's `sysrollback` rule: root-only (a
  non-root session reports "rollback needs root"),
  whole-system so it needs no row selection, and
  the same two-click confirm — the first click
  only reports "rollback confirm", the second
  restores the snapshot and consumes it, so a
  further Rollback reports "no update to roll
  back". The arm clears on success and on failure
  alike; any Remove press or row click disarms a
  pending Rollback confirm, and any Rollback press
  disarms a pending Remove confirm — but a row
  click disarms a Remove confirm only when it
  selects a different row: clicking the already-
  selected row leaves the Remove arm in place.
  CORRECTION: an earlier wording said "any Remove
  press or row click disarms a pending Rollback
  confirm, and vice versa"; the "vice versa" half
  overstated the row-click case, since a same-row
  click does not disarm the Remove confirm.
  Installs come from the Repo window, not here.
- **Repo**: shows the stored, signature-verified repo
  index — repository URL, index version, and name +
  version per entry. The window shows 8 rows; [Up]/[Dn]
  scroll the list when the index holds more (the index
  supports up to 64 entries), clamped to the first/last
  page, with a `repo: scroll N` marker only on a real
  move. An index that fails re-verification shows as
  "(no index downloaded)", never as stale data.
  [Update] fetches a fresh index through the shell's
  `pkg update` rule (it needs a configured network first
  — run DHCP from the Network window or the shell, or
  it reports "not configured" instead of fetching) and
  reloads the list in place; click a row to select it
  (highlighted, `repo: selected <name>`), then
  [Install] installs that package through the shell's
  `pkg install <name>` rule. Update and Install are
  both root-only, the shell's rule (a non-root session
  reports "update needs root" / "install needs root"):
  the pkg layer itself writes as uid 0, so without the
  handler checks a non-root desktop session could
  replace the stored index and install packages,
  bypassing the shell's root-only rule entirely — the
  Update check fires before the configured check,
  mirroring the shell, which refuses a non-root update
  before doing anything. Install with no selection
  only reports "install needs selection"; a failed
  install keeps the selection for a retry. [Fetch]
  downloads the selected package's file (`<name>.nxpkg`)
  to disk through the shell's `pkg fetch <name>` rule
  without installing it, so the file can later be
  installed from Files: root-only (a non-root session
  reports "fetch needs root"), Fetch with no selection
  only reports "fetch needs selection", a success
  clears the selection, and a failed fetch keeps it
  for a retry — a file that already exists is refused
  by pkg, never overwritten. The fetch
  and the install block the desktop loop while they
  run, like the Web fetch. Below the scroll buttons, a
  URL field and [Set repo] set the repository itself
  through the shell's `pkg repo <url>` rule — the
  desktop form of the one configuration Update needs
  (without a stored URL, Update has nothing to fetch):
  root-only (a non-root session reports "set needs
  root"), an empty field only reports "set needs url",
  a malformed URL fails with pkg's own reason and keeps
  the field for a retry, and a success reloads the
  "Repository:" line in place and clears the field.
  The field caps at 63 characters like the Web and
  Files fields. Click the field, type the URL, click
  Set repo.
- **Clock**: the ninth row of launcher column 2, a
  480×320 read-only window showing the system time with
  seconds from the same CMOS RTC read as the taskbar
  clock (24-hour `HH:MM:SS`, or 12-hour ` H:MM:SS AM/PM`
  following the Settings clock-format value), the
  calendar date `DD/MM/YYYY` from the CMOS date
  registers — `(unavailable)` when the registers fail
  validation, never an invented date — the uptime since
  boot (`Nd Nh Nm Ns`), and a format line naming the
  Settings source. It refreshes once per second like
  the Monitor window. Opening prints `Desktop: Clock
  opened` plus `clock: time/date/uptime` lines, so the
  serial log proves content, not just that a window
  opened; opening Clock again brings the open window
  forward instead of opening a second one.

## About window

The About window (Start launcher column 1, or the About
desktop icon) is a 360×240 read-only window: the version
line `nxtsOS v1.0.0`, `Original kernel, Multiboot, 32-bit
x86.`, `Not a Linux distribution or fork.`, the memory
total in KiB (the same frames × 4 figure the Monitor
window reports), and the desktop feature line (`Desktop:
icons, launcher, clock, settings, lock screen,
Calculator.`). Opening prints `Desktop: About opened`;
opening About again brings the open window forward
instead of opening a second one.

## Start launcher power action

Column 1 of the Start launcher ends with [Reboot]
(below [Exit desktop]; all earlier rows keep their
positions). It reboots through the shell's `reboot`
rule (keyboard-controller reset, no uid check — the
shell command has none either), and it needs a
two-click confirm like Files Delete: the first click
only arms it (`desktop: reboot confirm`, plus a
notification), the second click — after reopening the
launcher, which closes after every click — reboots
(`desktop: rebooting`). Any other launcher or icon
action disarms it, and a fresh desktop starts disarmed.
There is no power-off entry: the kernel has no ACPI
shutdown, so reboot is the only power action offered.

## Start launcher logout action

Column 1 of the Start launcher ends with [Logout]
(below [Reboot]; all earlier rows keep their
positions). It ends the session through the shell's
`logout` rule (the session's background jobs are
killed, the logout is audited, and the shell returns
to the login prompt — in setup mode, with no users
configured, that means straight back to a root shell
prompt), and it needs a two-click confirm like
Reboot: the first click only arms it (`desktop:
logout confirm`, plus a notification), the second
click — after reopening the launcher, which closes
after every click — logs out (`desktop: logging
out`). Any other launcher or icon action disarms it,
and a fresh desktop starts disarmed. The desktop
itself only records the request; the shell performs
the logout when the desktop returns, so the shell
and desktop paths share exactly one logout rule and
it runs once.

## Files window integration

The Files window's Open button opens the selected file
in the matching app: `.txt` in the Editor, `.bmp` in
the Viewer, `.nxpkg` installs the package through the
shell's `pkg install <file>` rule (signature-verified,
root-only — a non-root session reports "install needs
root" — with `files: installed <file>` on success and
the list re-enumerated in place, since the install wrote
new files; a failed install keeps the selection for a
retry), `.elf` runs the program through the shell's
background-job rule (`proc_bg_start` with the session
uid, the same rule the Calculator launcher entry uses —
`files: started <file>` on success, `files: run failed
<file>` on failure, selection kept either way since
running writes no files). `.nxupd` applies the bundle
through the shell's `sysupdate` rule (`pkg_sysupdate`,
two-phase and signature-verified, snapshot left for
`sysrollback` — root-only, a non-root session reports
"sysupdate needs root"). A system update replaces
installed packages, so it needs a two-click confirm like
Remove: the first Open only arms it (`files: sysupdate
confirm <file>`), the second Open on the same selected
bundle applies it (`files: sysupdate applied <file>`
beside pkg's own "System update complete" line, list
re-enumerated in place since the update wrote new files,
selection cleared; a failure prints `files: sysupdate
failed <file>`, clears the arm, and keeps the selection
for a retry). Selecting a different file, Refresh, or a
fresh desktop disarms it. A GUI program opens its window
and the desktop ticks it; a console program also runs,
but with no visible console on the desktop (its output
goes to the serial log) — the shell `run` stays the right
path for console programs. Other extensions show a notification and a
marker (`files: no viewer for <name>`). Close the app
window (its X button) before opening another file from
the list — the app window covers the Files window while
open. The Delete button removes the selected file, but
only on a second click: the first click only arms the
confirm (`files: delete confirm <name>`, also shown in
the preview box) and selecting a different file disarms
it; the confirming click deletes via the filesystem's
uid/mode check, so a file the session may not write
fails with `files: delete failed <name>` instead of a
silent no-op, and the list is re-enumerated in place
(scroll kept, selection cleared). The Rename row below
the buttons (the window is 480×352 for it) renames the
selected file through the same filesystem primitive as
the shell `mv`: click the field, type the new name,
click Rename. An empty field only reports
`files: rename needs name`; a rename onto an existing
name fails with `files: rename failed <name>` (never
an overwrite) and leaves the list and the typed name
alone for a retry; a success prints
`files: renamed <old> to <new>` and re-enumerates the
list in place. The Copy button beside Delete copies
the selected file through the same filesystem
primitive as the shell `cp`: type the destination
name in the same field, click Copy. The copy is
byte-exact and never overwrites (`files: copy failed
<name>` onto an existing name, `files: copied <old>
to <new>` on success, with the same in-place
re-enumeration). The Refresh button below the rename
row (the window is 480×384 for it) re-enumerates the
list in place without closing the window, so files
created or removed outside the window (shell, Editor
save) appear on demand (`files: refreshed`, scroll
kept and clamped, selection cleared); without it the
list stays stale until the window is reopened. The
Hash button beside Refresh is the desktop form of the
shell `sha256 <file>` command: it reads the selected
file (same read rule, same 64 KiB cap — a larger file
fails with `files: hash failed <name>` instead of
hashing a truncated prefix) and prints the full hex
beside `files: sha256 <name>`, showing it in the
preview box as a header line plus the 64-char hex as
two 32-char halves, so the whole hash is visible on
screen instead of clipped by the one-line preview. A
click with no selection only reports
`files: hash needs selection`, never hashes row 0;
the display clears on the next row click or Refresh,
and the draw gate requires the selection to still name
the hashed file, so a stale hash can never label
another file. No confirm: hashing reads and writes
nothing. The Mode row below the Refresh row (the
window is 480×424 for it) is the desktop form of the
shell `chmod <file> <mode>` command: click the field,
type the octal mode, click Chmod. It goes through the
same filesystem primitive as the shell (owner-or-root,
so a non-root session reports `files: chmod failed
<name>` on another user's file) with the shell's parse
rule exactly — an optional leading 0, then exactly 3
octal digits, anything else refused with
`files: chmod bad mode <mode>` and the field kept,
never a masked value, so 999 cannot silently become a
valid mode. A click with no selection only reports
`files: chmod needs selection`; an empty field only
reports `files: chmod needs mode`; a success prints
`files: chmod <name> mode <mode>` and clears the field,
so a second chmod types fresh. No confirm: a mode
change is reversible by changing it back, and the
owner can always chmod back even from mode 000. The
mode field is separate from the rename field, so typing
a mode never touches the new name.

## Terminal console package (term.nxpkg)

`userland/term.c` is a GUI application built on syscalls
9–13, like Calculator. Install it the same way
(`pkg install term.nxpkg`, never pre-seed a plain
`term.elf` on the same disk), then open it from Start →
Console. It opens a 480×320 window with a 15-line
scrollback and tells the user plainly that it cannot
run programs.

## Shell test commands (v0.10.0)

- `desktopautotest` — scripted desktop test (Settings icon,
  Idle value button, Start, Lock entry, unlock in setup
  mode, Terminal icon exit; the harness also checks clip
  redraw == full redraw and the cursor).
- `desktopsectest` — scripted adversarial desktop test
  (Settings Save on a root-owned settings.txt denied,
  wrong lock-screen password fails and the lock stays up;
  the harness also runs GUI-syscall and tampered-binary
  boots).
- `desktopcalctest` — scripted Calculator test (Calc icon,
  click the '7' key, screendump; the display must show
  '7', with the glyph pixel count checked against the
  font data).
- `desktoprepotest` — scripted Repo scroll test (a 10-entry
  index in an 8-row window: Dn to scroll 1 and 2, Dn past
  the end refused, Up back to 0, Up past the start
  refused).
- `desktoprepoapptest` — scripted Repo Update + Install
  test (Repo opens with no stored index, Update fetches
  the index, Install with no selection refused, row 0
  select, Install fetches + installs, Packages lists
  the installed entry).
- `desktoppackageapptest` — scripted Packages Remove test
  (Remove with no selection refused, row select, Remove
  confirms, Remove removes; shell `pkg list` after the
  desktop exit must list the kept package but not the
  removed one).
- `desktopfileinstalltest` — scripted Files Install test
  (row select, Open installs the package file, Open
  again refused as already installed; shell `pkg list`
  after the desktop exit must list it).
- `desktopfileruntest` — scripted Files Run test (row
  select, Open runs the program file as a background
  job, its window opens and closes; shell `jobs` after
  the desktop exit must list it).
- `desktopmonitorjobtest` — scripted Monitor Jobs test
  (a background job whose window was closed — the
  orphan case — Kill with no selection refused, row
  select, Kill arms, Kill kills; shell `jobs` after
  the desktop exit must not list it).
- `desktopreboottest` — scripted Reboot test (Reboot row
  first click only arms, second click confirms and
  resets; the harness waits for the shell prompt a
  second time in the same serial log, the second boot).
- `desktoplogouttest` — scripted Logout test (a running
  job's window closed first, so the logout's job kill
  has something to kill; Logout row arms, then confirms,
  desktop exits, shell logs out).
- `desktop10test` — scripted polish test (theme change,
  workspace pixels, snap/restore geometry).
- `desktopappstest` — scripted app test (launcher
  column 2, Files → Editor/Viewer).
- `desktop10sec` — scripted adversarial app test
  (garbage settings, sanitised/empty editor files,
  oversize/truncated BMP).
- `desktopwebtest` — scripted web test (slirp; run
  `dhcp` first, then fetch a host page).
- `desktopnonic` — scripted no-NIC test (boot with
  `-nic none`, open Network).
- `desktopfilesysupdtest` — scripted Files sysupdate
  test (bundle-only disk, arm + apply + same-version
  refusal, `pkg list` proof).
- `desktoprollbacktest` — scripted Packages rollback
  test (arm + apply + no-snapshot refusal, `pkg list`
  proof).
- `desktopreposettest` — scripted Repo set test
  (empty Set refused, type a slirp repo URL, Set,
  Update, Install, `pkg repo` + `pkg list` proof).
- `desktopdnssettest` — scripted Network DNS set test
  (empty Set refused, malformed address refused, type
  1.1.1.1, Set, `netinfo` proof).
- `desktopnetpingtest` — scripted Network Ping-host test
  (empty Ping refused, malformed address refused, ping
  10.0.2.2 for a reply, ping 192.0.2.1 for a timeout;
  ping changes no registry state, so the markers are
  the proof).
- `desktoprepofetchtest` — scripted Repo fetch test
  (Fetch with no selection refused, Set repo + Update,
  Fetch downloads sysinfo.nxpkg, a second Fetch is
  refused because the file already exists; `ls` must
  show sysinfo.nxpkg while `pkg list` still reports no
  packages installed, proving fetch is not install).
- `desktopfileshashtest` — scripted Files hash test
  (Hash with no selection refused, row 0 select, Hash
  prints the full hex; the harness checks it against
  hashlib of the same bytes, and shell `sha256` after
  the desktop exit must print the same value).
- `desktopmonitordisktest` — scripted Monitor disk test
  (Start, launcher Monitor row, a pixel scan of both
  Disk rows proving they drew, Terminal icon; the
  Monitor's open marker must report the same total and
  free sector counts as shell `fs` after the desktop
  exit).
- `desktopwebsavetest` — scripted Web save test
  (Save with no fetch refused, fetch a small slirp
  page, Save with an empty name refused, save as
  page.txt, a second save of the same name refused
  because the file already exists; shell `ls` must
  list page.txt and `cat page.txt` must print exactly
  the served bytes).
- `desktopfileschmodtest` — scripted Files chmod test
  (Chmod with no selection refused, Chmod with an
  empty mode refused, type 999 and Chmod refused as
  a bad mode, chmod to 600, chmod back to 644 —
  proving the field clears on success; shell `ls`
  after the desktop exit must report mode 420, the
  decimal form of 0644).
- `desktopreporoottest` — scripted Repo root-check test
  (as a non-root session, after root's shell `pkg
  update` stored the index: Update refused with
  "update needs root", Install refused with "install
  needs root"; shell `pkg list` after the desktop exit
  must still report no packages installed, and no
  "Installed sysinfo 1.0" line may appear).
- `desktopsettingsunlocktest` — scripted Settings Unlock
  test, two boots on one disk (the login loop halts
  after 3 failures, so the lock and the unlock cannot
  share a boot): boot 1 fails alice's login 3 times
  so the kernel itself records the lock; boot 2 as
  root runs the script (Unlock with an empty field
  refused, type alice, Unlock succeeds) and alice
  must then log in with the correct password, the
  behavioural proof the unlock landed; the same
  script as alice must refuse with "unlock needs
  root").
- `desktopunlocknousertest` — scripted Settings Unlock
  unknown-user test, one boot as root: type "ghost"
  in the Unlock field, press Unlock twice — both
  presses must report "settings: no such user ghost"
  (the second press proves the field survived the
  refusal), and no "settings: unlocked ghost" line
  may appear. The shell `unlock ghost` command
  refuses the same way ("unlock: no such user
  ghost"), while `unlock alice` still succeeds.

## Idle-lock trigger test (post-v1.0.0)

`tests/qemu_test_idle_lock.py` (fixtures from
`tests/qemu_test_idle_lock_setup.py`) is the first
test to wait out the idle timeout itself: one boot
as alice, `idle 1`, `desktop` — no lock screen in
the first 30 s (the no-early-lock property, now for
the desktop path), the lock screen within a further
90 s (about 60 s after desktop entry), then unlock
with the session password ("Desktop: unlocked").
Waiting out the 120-minute default is not feasible;
the 1-minute wait proves the same trigger code path.
No settings.txt is pre-seeded, so the shell's `idle
1` value survives desktop start unchanged.

The shell-prompt side has its own wait-out test:
`tests/qemu_test_shell_idle_lock.py` (fixtures from
`tests/qemu_test_shell_idle_lock_setup.py`) sets `idle 1` at the
shell prompt — no desktop entered — no lock in the first 30 s,
the "Session locked due to inactivity." notice plus the lock
prompt within a further 90 s, then unlock with the session
password and `whoami` proving the session continued.

## Honest limits (v0.10.0)

- Theme recolours chrome and panels only; client areas
  stay light in all themes.
- Editor cap 8192 bytes (refuses larger, never silently
  truncates); Viewer cap 128×128 24-bit BMP, 128 KiB.
- Web is text-only, 8192-byte body buffer with reported
  truncation; fetch blocks the desktop loop.
- Console package is a local echo console, not the shell.
- User-mode file writes via syscall are still capped at
  1024 bytes (unchanged).
- Graphical boot login is still NOT IMPLEMENTED (lock
  screen is graphical re-entry only).
- No icon themes beyond the built-in set, no per-window
  tiling layouts beyond snap halves/maximise.
