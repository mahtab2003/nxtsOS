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
  fire only when no text input has focus (lock screen,
  Settings search, Editor, Web address field, and focused
  user windows take priority, in that order).

Out-of-range values in `settings.txt` are ignored with a
serial marker (`settings: ignored invalid theme=99`);
non-numeric values are skipped. A corrupt settings file
cannot break the desktop — it starts with defaults.

New `settings.txt` keys (all optional, defaults shown):
`theme=0 accent=0 wallpaper=0 lowres=0 bigtext=0 shortcuts=0`.

## Workspaces and window snapping

- Two workspaces (WS1/WS2). The taskbar WS button toggles
  between them. Windows belong to the workspace they were
  opened on; other-workspace windows are hidden from the
  desktop, the taskbar buttons, and click detection.
- Snap keys (when no text input has focus): `[` snaps the
  topmost non-minimised window of the current workspace to
  the left half, `]` to the right half, `\` toggles
  maximise/restore. The first snap saves the window's
  geometry for restore.

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
- **Network**: MAC, DHCP state, IP/mask/gateway/DNS,
  RX/TX counters, with [Run DHCP] and [Ping gateway]
  buttons. With no NIC it reports `network: no device`
  and the buttons report "no device" instead of hanging.
- **Web**: text-only HTTP/HTTPS browser. One address
  field (`host[:port][/path]`, optional `http(s)://`
  prefix; HTTPS uses TLS port 443). Fetch blocks the
  desktop loop while it runs. The body buffer is 8192
  bytes: larger pages are truncated, not failed, and the
  truncation is reported (`web: truncated at 8192`, and
  the status line "8192 bytes (buffer full, may be
  truncated)"). Certificate failure reports
  `web: certificate refused`. Up/Down scroll the body.
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

## Files window integration

The Files window's Open button opens the selected file
in the matching app: `.txt` in the Editor, `.bmp` in
the Viewer. Other extensions show a notification and a
marker (`files: no viewer for <name>`). Close the app
window (its X button) before opening another file from
the list — the app window covers the Files window while
open. The file list itself is stale until the window is
reopened (unchanged from v0.8.0, documented there).

## Terminal console package (term.nxpkg)

`userland/term.c` is a GUI application built on syscalls
9–13, like Calculator. Install it the same way
(`pkg install term.nxpkg`, never pre-seed a plain
`term.elf` on the same disk), then open it from Start →
Console. It opens a 480×320 window with a 15-line
scrollback and tells the user plainly that it cannot
run programs.

## Shell test commands (v0.10.0)

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
