# nxtsOS v0.7.4 — Security Report (adversarial review)

Method: third-party-style review of the changed code, plus
the existing regression suites (GUI security, v071, base).

## Changes reviewed

- Cursor save/restore: buffer is 13x17 u32 on the stack of
  the WM (static, 221 entries), indices are bounded by
  construction (dx 0-12, dy 0-16). Save/restore skip
  out-of-screen pixels by explicit bounds checks; restore
  only writes pixels that were saved, and only if the
  saved position matches the old cursor position, else it
  falls back to a full redraw. No user-controlled data
  reaches the buffer except mouse coordinates, which are
  already clamped by the mouse driver to the screen.
- Dirty-rect redraw: skipping a window that does not
  overlap the dirty rect cannot hide or expose pixels
  incorrectly, because a non-overlapping window's rect
  cannot intersect the dirty area by definition; overlapping
  windows are drawn in z-order, so focus/occlusion is
  preserved. The 200,000-pixel upgrade to full redraw is a
  performance heuristic only, not a correctness boundary.
- Throttling: redraw timing only, no state change. Window
  positions/sizes are updated immediately in the drag/
  resize branches; only the *display* of the new position
  is deferred by up to 30 ms. Autotest position checks
  therefore still pass (they check state, not pixels).
- fb fill/text/char optimisations: same pixels written,
  only the loop structure changed (row pointer, per-glyph
  clip). No new bounds: fill_clip and text_clip still
  clamp to the screen before writing.

## Findings

- No exploitable findings in the v0.7.4 changes.
- Unchanged limits: no package signing, CTR encryption
  is confidentiality-only, password KDF is not
  memory-hard, no passphrase change/recovery.
