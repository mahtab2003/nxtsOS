# nxtsOS v0.10.0 — Security Report (Phase 10 adversarial test)

Method (per the standing rule): after the release build,
attack the system as a third-party tester would — here,
at the application layer — fix what is exploitable,
retest, and record what is not exploitable honestly.
All findings below were retested on the final ISO.

## Finding 1 (REAL BUG, FIXED + RETESTED): HTTP/HTTPS clients failed on oversize bodies

- Attack: fetch a 20000-byte page into the Web
  window's 8192-byte buffer (host server on
  127.0.0.1:18081, slirp, guest `dhcp` then
  desktopwebtest).
- Result before fix: the shell's `http` command
  reported "http: failed" even though the server
  received the GET and sent the full response. Root
  cause in `net_http_get` (net/net.c) and identically
  in `net_https_get` (net/tls.c): the read loop
  returned -1 the moment the stream would exceed
  `max - 1`, instead of truncating. The desktop's
  truncation marker could never have fired either:
  its condition (`body_len >= 8192`) is unreachable
  because headers consume buffer space first.
- Exploitability: availability/integrity of the Web
  window and shell fetch — any page over ~8 KB was
  unfetchable, and the failure was silent in the
  desktop (no marker at all: the fetch handler only
  printed on truncation).
- Fix: both clients now truncate-and-drain — the
  buffer fills, the rest of the response is drained
  (so Content-Length completion still works), and a
  new `net_fetch_truncated()` flag reports it. The
  desktop marker now keys off the flag, and the fetch
  handler also prints `web: fetched N bytes`,
  `web: fetch failed`, and `web: certificate refused`
  so no outcome is silent. The shell prints
  "(truncated)" on truncated fetches; non-truncated
  output is byte-identical to before.
- Retest: shell `http: 8076 bytes (truncated)` on the
  20000-byte page (8076 = 8191 stored − ~115 header
  bytes); desktopwebtest "web: truncated at 8192" —
  PASS. All net/TLS regression suites re-run after
  the fix — PASS (net, net peer, TLS, net security).

## Finding 2 (REGRESSION, FIXED + RETESTED): classic desktop autotest truncated by max_step

- Attack: none — found by running the v0.8.0 suite
  against the Phase 10 build.
- Result: `tests/qemu_test_desktop.py` failed with
  "TIMEOUT: desktopautotest" — Settings opened, then
  nothing. Root cause: the new max_step chain gave
  mode 1 (classic autotest) a max step of 3 instead
  of 11, so the script stopped after moving the mouse
  to the Idle button without ever clicking. Modes 2
  and 3 were unaffected (their values were preserved).
- Fix: mode 1 → 11, mode 8 → 3 explicitly.
- Retest: desktop test PASS; v0.9.0 ISO bisected
  clean on the same harness (proving the regression
  was in the new code, not the environment).

## Attacks that did NOT break the system (all retested)

- Garbage `settings.txt` (theme=99, wallpaper=5,
  accent=xx, idle=abc): out-of-range values ignored
  with markers, non-numeric skipped, desktop starts
  with defaults. No crash, no hang, no fault.
- Non-text editor file (control bytes 0x01/0x02,
  high bytes 0xFF/0x7F): sanitised to `?` on load
  (4 bytes), file opens normally. No byte reaches
  the screen or the save path unsanitised.
- Empty file: opens as 0 bytes, editable, saveable.
- Oversize image (200×200 BMP header, no pixel
  data): refused as oversize BEFORE any pixel read —
  the truncated pixel data is never touched.
  Valid 64×64 BMP opens. Non-BMP, non-24-bit and
  over-128 KiB inputs are refused by their own
  checks (same code path, same bounds-first order).
- Oversize editor file (>8192 bytes): refused, never
  silently truncated (the refusal is the design: a
  text editor must not quietly drop content).
- Huge web page (20000 bytes): truncated with a
  marker after Finding 1's fix (see above).
- No-NIC Network window: `network: no device`, no
  hang, no fault; DHCP/ping buttons report no device.
- Window-count pressure: the apps script peaks at 8
  windows (MAX_WINDOWS), never over; the eighth
  opens, the ninth would be refused by wm_create.
- Prior suites re-run (see TEST_REPORT.md): GUI
  security pixels identical, desktop security
  (non-admin save denied, lock held, guibad PASS,
  tampered calc refused), package security (bad
  hash/size/path/self-dep/cycle/oversize refused),
  network security (flood, DNS pointer, cert
  negatives) — all PASS.

## Honest limits (not exploitable, recorded)

- Editor/Viewer/Web caps are enforced by refusal or
  reported truncation, but a hostile file can still
  waste the user's time (e.g. a 128 KiB BMP that is
  all header lies is read fully before refusal —
  bounded by the 128 KiB cap).
- The Web window fetches over the same TLS client as
  v0.9.0: TOFU self-signed roots only, xorshift RNG,
  no revocation — do not fetch real secrets through
  it (unchanged from v0.9.0).
- Fetch blocks the desktop loop: a slow server stalls
  the whole desktop until the 10-second read deadline
  or close. That is a responsiveness limit, not a
  bypass — no input is processed out of order while
  blocked, and the loop resumes afterwards.
- Calculator overflow input was not separately fuzzed
  in this release beyond the existing '7'-key
  verification; the calculator clamps values to
  ±9999 by design and has no division (repeated
  subtraction), so the overflow surface is the clamp
  itself.
