# nxtsOS v0.8.0 — Security Report (Phase 8.3, adversarial test)

Attacker view for this release: Phase 7's view (window
larger than the screen, negative coordinates, huge window
counts, mouse packets out of range, a program drawing
outside its window, a program trying to read another
window's pixels) plus the Phase 8 additions: lock-screen
bypass attempts, settings a non-admin user must not
change, launcher entries pointing at tampered programs,
and malformed GUI syscalls.

## Test: tests/security_test_desktop.py — PASS (all boots)

Disk (built by tests/security_test_desktop_setup.py):
users root/rootpass and user/userpass, a root-owned
settings.txt (0600, uid 0), guibad.elf, calc.nxpkg (not
pre-installed, and no plain calc.elf pre-seeded, so the
install in Boot C is not refused as "file already exists
on disk").

### Boot A — non-admin settings + lock bypass (as user)

Scripted via `desktopsectest` (mode 2 of the desktop
loop): open Settings, click Save, open the launcher,
click Lock, type the wrong password "wrong", press Enter.

- "Desktop settings save failed: permission denied"
  — FOUND. The save goes through `fs_write_as` with the
  session uid, so a non-root user cannot overwrite a
  root-owned 0600 settings file. The failure is shown in
  the Settings status line AND logged to serial (added
  in this release so the denial is auditable, not only
  drawn in the window).
- "Desktop settings saved" — ABSENT (correct: it must
  not silently succeed).
- "Desktop: lock screen shown" — FOUND.
- "Desktop: lock password failed (1/3)" — FOUND.
- "Desktop: unlocked" — ABSENT (the lock held after the
  wrong password).
- "desktopsectest returned" — ABSENT (the desktop did
  not exit from under the lock screen; the harness ended
  the run).
- No EXCEPTION/PANIC/page fault.

### Boot B — malformed GUI syscalls (as root, no desktop)

`guibad.elf` (userland/guibad.c) calls, from the text
shell with no desktop running: GUI_OPEN with a null
title pointer, GUI_OPEN with width 5000 (over the 4096
cap), GUI_RECT with 5000x5000, GUI_TEXT containing a
non-printable byte (valid pointer, bad content), GUI_EVENT
with a null output pointer, GUI_CLOSE with no window.

- "guibad PASS (all GUI calls rejected)" — FOUND.
  Every call returned -1: the syscall handler validates
  pointers (range-checked per byte) and sizes before any
  window code runs, and GUI_OPEN fails cleanly when the
  desktop is not active. No kernel fault, no window
  created from a bad call.

### Boot C — tampered launcher program (as root)

Install calc.nxpkg ("Installed calc 1.0"), terminate,
flip one byte at offset 1000 in the installed calc.elf's
data on disk (sector 44 in the test run), boot again,
`runbg calc.elf` (the same proc_bg_start/elf loader path
the desktop launcher uses for Calculator).

- "runbg: cannot start calc.elf" — FOUND. The loader's
  Phase 6 registry hash check (elf_create_proc →
  pkg_verify_file) refuses the tampered file even though
  it is otherwise a valid ELF.
- "calc 1.0  depends:" — FOUND in `pkg list` (the
  registry entry itself is intact; only the tampered
  file is refused).

## Other adversarial suites rerun for v0.8.0

- tests/security_test_gui.py (Phase 7 view): PASS,
  screendump counts pixel-identical to v0.7.0–0.7.4.
- tests/security_test_pkg.py (Phase 6 view): PASS
  (bad hash/size/path/abs/self-dep/cycle/dependency/
  huge refused; tampered hello.elf refused on re-boot).
- tests/qemu_test_enc.py covers the encryption view
  (wrong passphrase halts, raw image leaks no plaintext
  — carried from v0.6.0, rerun PASS here).

## Findings: none exploitable left open

No exploitable finding was found in this release's
desktop attack surface. Recorded limits (not
vulnerabilities in the tested threat model, but honest
bounds):

- The event queue holds 16 events per user window and
  drops further events silently; a fast input source can
  lose clicks/keys, but cannot corrupt memory or read
  another window (the queue is per-window, and
  GUI_RECT/GUI_TEXT are clipped to the caller's own
  client rect by fb_fill_rect_clip/fb_draw_text_clip).
- GUI_TEXT/GUI_RECT coordinates are client-relative and
  clipped, but a user program can still draw anywhere
  inside its own window, including over its own title
  bar area? No — the clip rect is the client area
  (x+1, y+TITLE_H+1, w-2, h-TITLE_H-2), so title/border
  pixels are outside the clip and cannot be overwritten
  by the app.
- Three wrong lock passwords halt the whole system
  (by design, same as text login lockout); this is a
  denial-of-service against the local session only, not
  a bypass, and it matches the Phase 5 behaviour.
- No package signing (Phase 6 limit, unchanged): the
  registry hash check proves a file matches what was
  installed, not who published it.
- Settings load ignores malformed lines rather than
  rejecting the whole file; a corrupted settings.txt
  therefore falls back to defaults for the bad keys
  instead of failing the desktop start.
