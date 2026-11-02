#include "editor.h"
#include "console.h"
#include "users.h"
#include "../drivers/keyboard.h"
#include "../drivers/serial.h"
#include "../fs/vfs.h"

/* Nano-like full-screen editor. File-scope state only: the
   kernel stack is 16 KiB, and the edit buffer alone is 128 KiB.
   Line model: one flat buffer, lines split on '\n'. The cursor
   is (cy, cx): line index + column within that line. The
   window shows 23 text lines (rows 0-22); row 23 is the status
   row (filename, modified mark, cursor position, or a message
   / prompt); row 24 is the key hints. Lines longer than 80
   columns are truncated on screen (the cursor display clamps
   at column 79); editing still works at any column.
   Load normalisation (documented, not hidden): tabs expand to
   4 spaces (no tab-stop model, so columns are normalised
   rather than corrupted); carriage returns are dropped (CRLF
   becomes LF); other control bytes are dropped (the editor is
   a text editor, not a hex editor — a NUL or control byte
   would otherwise render as garbage and could never be typed
   back). A save therefore writes the normalised text, which
   is the text the user saw and edited. */

#define EDIT_MAX 131072
#define EDIT_TEXT_ROWS 23
#define EDIT_STATUS_ROW 23
#define EDIT_HINT_ROW 24

static char edit_buf[EDIT_MAX + 1];
static u32 edit_len = 0; /* bytes used, excluding the NUL */
static u32 edit_cy = 0, edit_cx = 0; /* cursor: line, column */
static u32 edit_top = 0; /* first visible line */
static char edit_name[32];
static int edit_modified = 0;
static u32 edit_uid = 0;
static char edit_cut[1025];
static u32 edit_cut_len = 0; /* 0 = nothing cut */
static char edit_msg[96]; /* status-row message, "" = none */
/* Scratch for building one undo record (cut/paste runs are
   not contiguous in the buffer). File-scope, never stack:
   the kernel stack is 16 KiB. Single-threaded use only —
   record_mutation copies it into the record at once. */
static char edit_scratch[1025];

/* Undo/redo: an OPERATION LOG, not snapshots (a snapshot per
   level would cost 128 KiB each). Every mutation in this
   editor is a single-char insert/delete, a '\n' insert/delete,
   or a <=1025-byte cut/paste, so one record covers every
   operation exactly: type 0 = text was INSERTED at off (undo
   deletes it); type 1 = text was DELETED at off (undo
   re-inserts it). Consecutive single-char inserts at
   contiguous offsets coalesce (typing a word = one undo
   step); consecutive backspaces coalesce backwards and
   consecutive Del presses at one position coalesce forwards
   (same contiguity argument, checked in the do_* wrappers).
   Coalescing only ever joins chars that were adjacent in the
   buffer at deletion/insertion time, so undoing a coalesced
   record restores exactly what was there. When a stack is
   full the OLDEST record is dropped (its text stays in the
   buffer — only the ability to undo that step is lost, and
   later records' offsets stay valid because the dropped
   record's text was never reverted). A new mutation clears
   the redo stack. Undo is buffer-local: a saved file stays
   saved (the modified flag returns, the disk file does not
   roll back — documented, not a bug). */
#define EDIT_UNDO_DEPTH 64
#define EDIT_UNDO_INS 0
#define EDIT_UNDO_DEL 1
typedef struct { u8 type; u32 off; u32 len; char text[1025]; } edit_undo_t;
static edit_undo_t edit_undo[EDIT_UNDO_DEPTH];
static u32 edit_undo_n = 0;
static edit_undo_t edit_redo[EDIT_UNDO_DEPTH];
static u32 edit_redo_n = 0;

static int wait_key(void) {
    for (;;) {
        keyboard_poll();
        int c = keyboard_getchar();
        if (c >= 0) return c;
        __asm__ volatile ("hlt");
    }
}

/* --- line helpers (offsets into edit_buf) --- */
static u32 line_count(void) {
    u32 n = 1;
    for (u32 i = 0; i < edit_len; i++)
        if (edit_buf[i] == '\n') n++;
    return n;
}
static u32 line_start(u32 cy) {
    u32 line = 0, off = 0;
    while (line < cy && off < edit_len) {
        if (edit_buf[off] == '\n') line++;
        off++;
    }
    return off;
}
static u32 line_len(u32 cy) {
    u32 start = line_start(cy);
    u32 n = 0;
    while (start + n < edit_len && edit_buf[start + n] != '\n') n++;
    return n;
}
static u32 cursor_off(void) {
    return line_start(edit_cy) + edit_cx;
}
static void clamp_cursor(void) {
    u32 lc = line_count();
    if (edit_cy >= lc) edit_cy = lc - 1;
    u32 ll = line_len(edit_cy);
    if (edit_cx > ll) edit_cx = ll;
}
static void keep_visible(void) {
    if (edit_cy < edit_top) edit_top = edit_cy;
    if (edit_cy >= edit_top + EDIT_TEXT_ROWS) edit_top = edit_cy - EDIT_TEXT_ROWS + 1;
}

/* --- rendering (buffer-only console APIs, no serial) --- */
static void draw_row_text(u32 row, const char *s) {
    u32 col = 0;
    while (s[col] && col < 80) {
        console_put_at(row, col, s[col]);
        col++;
    }
    while (col < 80) { console_put_at(row, col, ' '); col++; }
}
static void render(void) {
    for (u32 r = 0; r < EDIT_TEXT_ROWS; r++) {
        u32 li = edit_top + r;
        if (li < line_count()) {
            u32 start = line_start(li);
            u32 ll = line_len(li);
            u32 col = 0;
            while (col < ll && col < 80) {
                console_put_at(r, col, edit_buf[start + col]);
                col++;
            }
            while (col < 80) { console_put_at(r, col, ' '); col++; }
        } else {
            for (u32 col = 0; col < 80; col++) console_put_at(r, col, ' ');
        }
    }
    /* Status row: filename, modified mark, cursor position —
       or the current message, which overrides the position. */
    char st[96];
    u32 p = 0;
    if (edit_msg[0]) {
        const char *m = edit_msg;
        while (*m && p < 80) st[p++] = *m++;
    } else {
        const char *n = edit_name;
        while (*n && p < 78) st[p++] = *n++;
        if (edit_modified && p < 79) st[p++] = '*';
        /* "  Ln %u, Col %u" — built without printf (the editor
           never uses console_printf: serial spam). */
        if (p < 78) st[p++] = ' ';
        if (p < 78) st[p++] = ' ';
        st[p++] = 'L'; st[p++] = 'n'; st[p++] = ' ';
        u32 v = edit_cy + 1;
        char rev[10]; int rn = 0;
        if (v == 0) rev[rn++] = '0';
        else while (v > 0) { rev[rn++] = (char)('0' + (v % 10u)); v /= 10u; }
        while (rn > 0 && p < 79) st[p++] = rev[--rn];
        if (p < 79) st[p++] = ',';
        if (p < 79) st[p++] = ' ';
        st[p++] = 'C'; st[p++] = 'o'; st[p++] = 'l'; st[p++] = ' ';
        v = edit_cx + 1; rn = 0;
        if (v == 0) rev[rn++] = '0';
        else while (v > 0) { rev[rn++] = (char)('0' + (v % 10u)); v /= 10u; }
        while (rn > 0 && p < 79) st[p++] = rev[--rn];
    }
    st[p] = 0;
    draw_row_text(EDIT_STATUS_ROW, st);
    draw_row_text(EDIT_HINT_ROW, "^O Save ^X Exit ^W Search ^K Cut ^U Paste ^G Help ^Z Undo ^Y Redo");
    u32 crow = edit_cy - edit_top;
    if (crow >= EDIT_TEXT_ROWS) crow = EDIT_TEXT_ROWS - 1;
    console_set_cursor(crow, edit_cx);
    console_present();
}
static void render_prompt(const char *label, const char *input) {
    /* Status row only: the prompt label + input. The text rows
       stay as last rendered; the cursor moves to the input. */
    char row[96];
    u32 p = 0;
    while (label[p] && p < 80) { row[p] = label[p]; p++; }
    u32 col = p;
    const char *in = input;
    while (*in && p < 80) row[p++] = *in++;
    while (p < 80) row[p++] = ' ';
    row[80] = 0;
    draw_row_text(EDIT_STATUS_ROW, row);
    console_set_cursor(EDIT_STATUS_ROW, col + (u32)strlen(input));
    console_present();
}
static void set_msg(const char *m) {
    u32 i = 0;
    while (m[i] && i < sizeof(edit_msg) - 1) { edit_msg[i] = m[i]; i++; }
    edit_msg[i] = 0;
}
static void clear_msg(void) { edit_msg[0] = 0; }

/* --- buffer mutations (all set edit_modified) --- */
static int buf_insert(u32 off, char ch) {
    if (edit_len >= EDIT_MAX) return -1;
    for (u32 i = edit_len; i > off; i--) edit_buf[i] = edit_buf[i - 1];
    edit_buf[off] = ch;
    edit_len++;
    edit_buf[edit_len] = 0;
    return 0;
}
static void buf_delete(u32 off) {
    if (off >= edit_len) return;
    for (u32 i = off; i + 1 < edit_len; i++) edit_buf[i] = edit_buf[i + 1];
    edit_len--;
    edit_buf[edit_len] = 0;
}
static void buf_delete_range(u32 off, u32 count) {
    if (off >= edit_len) return;
    if (off + count > edit_len) count = edit_len - off;
    for (u32 i = off; i + count < edit_len; i++) edit_buf[i] = edit_buf[i + count];
    edit_len -= count;
    edit_buf[edit_len] = 0;
}

/* --- undo/redo stacks --- */
/* Push onto a stack, dropping the oldest record when full. */
static void undo_stack_push(edit_undo_t *stack, u32 *n, const edit_undo_t *rec) {
    if (*n >= EDIT_UNDO_DEPTH) {
        for (u32 i = 1; i < EDIT_UNDO_DEPTH; i++) stack[i - 1] = stack[i];
        (*n)--;
    }
    stack[(*n)++] = *rec;
}
/* Record a fresh user mutation: clears redo, then pushes. */
static void record_mutation(u8 type, u32 off, const char *text, u32 len) {
    edit_redo_n = 0;
    edit_undo_t rec;
    rec.type = type;
    rec.off = off;
    rec.len = len;
    for (u32 i = 0; i < len && i < sizeof(rec.text); i++) rec.text[i] = text[i];
    undo_stack_push(edit_undo, &edit_undo_n, &rec);
}
static void cursor_to_off(u32 off) {
    if (off > edit_len) off = edit_len;
    u32 line = 0, ls = 0, p = 0;
    while (p < off) {
        if (edit_buf[p] == '\n') { line++; ls = p + 1; }
        p++;
    }
    edit_cy = line;
    edit_cx = off - ls;
}
static void buf_insert_range(u32 off, const char *text, u32 len) {
    for (u32 i = 0; i < len; i++) buf_insert(off + i, text[i]);
}
static void do_undo(void) {
    if (edit_undo_n == 0) { set_msg("edit: nothing to undo"); return; }
    edit_undo_t rec = edit_undo[edit_undo_n - 1];
    if (rec.type == EDIT_UNDO_DEL && edit_len + rec.len > EDIT_MAX) {
        set_msg("edit: buffer full (max 131072 bytes)");
        return; /* record stays: undo is still possible later */
    }
    edit_undo_n--;
    if (rec.type == EDIT_UNDO_INS) {
        buf_delete_range(rec.off, rec.len);
        cursor_to_off(rec.off);
    } else {
        buf_insert_range(rec.off, rec.text, rec.len);
        cursor_to_off(rec.off + rec.len);
    }
    undo_stack_push(edit_redo, &edit_redo_n, &rec);
    edit_modified = 1;
}
static void do_redo(void) {
    if (edit_redo_n == 0) { set_msg("edit: nothing to redo"); return; }
    edit_undo_t rec = edit_redo[edit_redo_n - 1];
    if (rec.type == EDIT_UNDO_INS && edit_len + rec.len > EDIT_MAX) {
        set_msg("edit: buffer full (max 131072 bytes)");
        return; /* record stays: redo is still possible later */
    }
    edit_redo_n--;
    if (rec.type == EDIT_UNDO_INS) {
        buf_insert_range(rec.off, rec.text, rec.len);
        cursor_to_off(rec.off + rec.len);
    } else {
        buf_delete_range(rec.off, rec.len);
        cursor_to_off(rec.off);
    }
    undo_stack_push(edit_undo, &edit_undo_n, &rec);
    edit_modified = 1;
}

static void do_insert_char(char ch) {
    u32 off = cursor_off();
    if (buf_insert(off, ch) != 0) { set_msg("edit: buffer full (max 131072 bytes)"); return; }
    /* Coalesce with a directly preceding insert record. */
    if (edit_undo_n > 0) {
        edit_undo_t *top = &edit_undo[edit_undo_n - 1];
        if (top->type == EDIT_UNDO_INS && top->off + top->len == off &&
            top->len < 1024) {
            top->text[top->len++] = ch;
            edit_redo_n = 0;
            edit_cx++;
            edit_modified = 1;
            return;
        }
    }
    record_mutation(EDIT_UNDO_INS, off, &ch, 1);
    edit_cx++;
    edit_modified = 1;
}
static void do_enter(void) {
    u32 off = cursor_off();
    if (buf_insert(off, '\n') != 0) { set_msg("edit: buffer full (max 131072 bytes)"); return; }
    record_mutation(EDIT_UNDO_INS, off, "\n", 1);
    edit_cy++;
    edit_cx = 0;
    edit_modified = 1;
}
static void do_backspace(void) {
    if (edit_cx > 0) {
        u32 off = cursor_off() - 1;
        char ch = edit_buf[off];
        buf_delete(off);
        if (edit_undo_n > 0) {
            edit_undo_t *top = &edit_undo[edit_undo_n - 1];
            if (top->type == EDIT_UNDO_DEL && top->off == off + 1 &&
                top->len < 1024) {
                /* Prepend: this char stood just before the run. */
                for (u32 i = top->len; i > 0; i--) top->text[i] = top->text[i - 1];
                top->text[0] = ch;
                top->len++;
                top->off = off;
                edit_redo_n = 0;
                edit_cx--;
                edit_modified = 1;
                return;
            }
        }
        record_mutation(EDIT_UNDO_DEL, off, &ch, 1);
        edit_cx--;
        edit_modified = 1;
    } else if (edit_cy > 0) {
        /* Join with the previous line: delete the newline
           before this line, cursor lands at the end of the
           previous line. */
        u32 off = line_start(edit_cy) - 1;
        u32 prev_len = line_len(edit_cy - 1);
        buf_delete(off);
        if (edit_undo_n > 0) {
            edit_undo_t *top = &edit_undo[edit_undo_n - 1];
            if (top->type == EDIT_UNDO_DEL && top->off == off + 1 &&
                top->len < 1024) {
                for (u32 i = top->len; i > 0; i--) top->text[i] = top->text[i - 1];
                top->text[0] = '\n';
                top->len++;
                top->off = off;
                edit_redo_n = 0;
                edit_cy--;
                edit_cx = prev_len;
                edit_modified = 1;
                return;
            }
        }
        record_mutation(EDIT_UNDO_DEL, off, "\n", 1);
        edit_cy--;
        edit_cx = prev_len;
        edit_modified = 1;
    }
}
static void do_delete(void) {
    if (edit_cx < line_len(edit_cy)) {
        u32 off = cursor_off();
        char ch = edit_buf[off];
        buf_delete(off);
        if (edit_undo_n > 0) {
            edit_undo_t *top = &edit_undo[edit_undo_n - 1];
            if (top->type == EDIT_UNDO_DEL && top->off == off &&
                top->len < 1024) {
                /* Repeated Del at one position: the next char
                   slides into the same slot, so it appends. */
                top->text[top->len++] = ch;
                edit_redo_n = 0;
                edit_modified = 1;
                return;
            }
        }
        record_mutation(EDIT_UNDO_DEL, off, &ch, 1);
        edit_modified = 1;
    } else if (edit_cy + 1 < line_count()) {
        /* Join with the next line: delete the newline after
           this line. */
        u32 off = cursor_off();
        buf_delete(off);
        if (edit_undo_n > 0) {
            edit_undo_t *top = &edit_undo[edit_undo_n - 1];
            if (top->type == EDIT_UNDO_DEL && top->off == off &&
                top->len < 1024) {
                top->text[top->len++] = '\n';
                edit_redo_n = 0;
                edit_modified = 1;
                return;
            }
        }
        record_mutation(EDIT_UNDO_DEL, off, "\n", 1);
        edit_modified = 1;
    }
}
static void do_cut(void) {
    u32 ll = line_len(edit_cy);
    if (ll > 1024) { set_msg("edit: line too long to cut (max 1024 bytes)"); return; }
    u32 start = line_start(edit_cy);
    for (u32 i = 0; i < ll; i++) edit_cut[i] = edit_buf[start + i];
    edit_cut[ll] = 0;
    edit_cut_len = ll;
    /* Record the deleted run BEFORE deleting it: the run is
       the line plus its newline (or the preceding newline +
       the line for the last line, or just the line when it is
       the only line) — at most 1025 bytes, fits the record. */
    if (edit_cy + 1 < line_count()) {
        for (u32 i = 0; i < ll; i++) edit_scratch[i] = edit_buf[start + i];
        edit_scratch[ll] = '\n';
        record_mutation(EDIT_UNDO_DEL, start, edit_scratch, ll + 1);
        buf_delete_range(start, ll + 1);
    } else if (edit_cy > 0) {
        edit_scratch[0] = '\n';
        for (u32 i = 0; i < ll; i++) edit_scratch[i + 1] = edit_buf[start + i];
        record_mutation(EDIT_UNDO_DEL, start - 1, edit_scratch, ll + 1);
        buf_delete_range(start - 1, ll + 1);
        edit_cy--;
    } else {
        for (u32 i = 0; i < ll; i++) edit_scratch[i] = edit_buf[start + i];
        record_mutation(EDIT_UNDO_DEL, start, edit_scratch, ll);
        buf_delete_range(start, ll);
    }
    edit_cx = 0;
    clamp_cursor();
    edit_modified = 1;
}
static void do_paste(void) {
    if (edit_cut_len == 0) { set_msg("edit: nothing to paste"); return; }
    if (edit_len + edit_cut_len + 1 > EDIT_MAX) {
        set_msg("edit: buffer full (max 131072 bytes)");
        return;
    }
    u32 off = cursor_off();
    for (u32 i = 0; i < edit_cut_len; i++) buf_insert(off + i, edit_cut[i]);
    buf_insert(off + edit_cut_len, '\n');
    /* Record the pasted run (cut text + newline) as one step. */
    for (u32 i = 0; i < edit_cut_len; i++) edit_scratch[i] = edit_cut[i];
    edit_scratch[edit_cut_len] = '\n';
    record_mutation(EDIT_UNDO_INS, off, edit_scratch, edit_cut_len + 1);
    edit_cy++;
    edit_cx = 0;
    edit_modified = 1;
}
static void do_search(void) {
    /* Prompt on the status row: printable + backspace + Enter.
       Empty input is "Not found" (no-op, cursor unchanged). */
    char needle[64];
    u32 nlen = 0;
    needle[0] = 0;
    for (;;) {
        render_prompt("Search: ", needle);
        int c = wait_key();
        if (c == '\n') break;
        if (c == '\b') {
            if (nlen > 0) needle[--nlen] = 0;
            continue;
        }
        if (c >= 32 && c < 127 && nlen < sizeof(needle) - 1) {
            needle[nlen++] = (char)c;
            needle[nlen] = 0;
        }
        /* Any other key (arrows, Ctrl, ...) is ignored here. */
    }
    if (nlen == 0) { set_msg("Not found"); return; }
    u32 start = cursor_off() + 1;
    u32 found = 0xFFFFFFFFu;
    /* First pass: after the cursor. Second pass (wrap once):
       from the start up to and including the cursor position. */
    for (u32 pass = 0; pass < 2 && found == 0xFFFFFFFFu; pass++) {
        u32 lo = (pass == 0) ? start : 0;
        u32 hi = (pass == 0) ? edit_len : start;
        if (lo > edit_len) lo = edit_len;
        if (hi > edit_len) hi = edit_len;
        for (u32 i = lo; i + nlen <= hi; i++) {
            u32 j = 0;
            while (j < nlen && edit_buf[i + j] == needle[j]) j++;
            if (j == nlen) { found = i; break; }
        }
    }
    if (found == 0xFFFFFFFFu) { set_msg("Not found"); return; }
    /* Move the cursor to the match start. */
    u32 line = 0, off = 0;
    while (off < found) {
        if (edit_buf[off] == '\n') line++;
        off++;
    }
    edit_cy = line;
    edit_cx = found - line_start(line);
    clear_msg();
    keep_visible();
}
static void do_help(void) {
    static const char *lines[] = {
        "nxtsOS editor — keys",
        "",
        "Arrows: move cursor    Home/End: line start/end",
        "PgUp/PgDn: page (23 lines)",
        "Type: insert    Enter: split line",
        "Backspace: delete back (joins at line start)",
        "Delete: delete forward (joins at line end)",
        "^O: save (prompts File to write; Enter keeps name)",
        "^X: exit (asks Save changes? y/n/c if modified)",
        "^W: search (next match after cursor, wraps once)",
        "^K: cut cursor line (max 1024 bytes)",
        "^U: paste cut line below the cursor line",
        "^Z: undo last change (typing runs undo as one step)",
        "^Y: redo (cleared by any new change)",
        "Limits: 128 KiB file, no highlighting.",
        "",
        "Press any key to return to editing.",
    };
    for (u32 r = 0; r < EDIT_TEXT_ROWS; r++) {
        if (r < 17) draw_row_text(r, lines[r]);
        else draw_row_text(r, "");
    }
    draw_row_text(EDIT_STATUS_ROW, "Help — press any key to return");
    draw_row_text(EDIT_HINT_ROW, "");
    console_set_cursor(EDIT_STATUS_ROW, 0);
    console_present();
    (void)wait_key();
}

/* --- save --- */
/* Save the buffer to `name`. Returns 0 on success, -1 on
   failure (status message set, buffer preserved). Mode: an
   existing file keeps its mode, a new file gets 0644.
   Ownership: a save rewrites the entry with the writer's uid,
   so when root saves another user's file the old owner is
   restored via fs_chown_as. A non-root writer saving a
   foreign world-writable file cannot restore (only root can
   chown) — that case reports the owner change instead of
   hiding it. */
static int do_save_to(const char *name) {
    struct fs_stat st;
    int existed = (fs_stat_as(name, &st, edit_uid) == 0);
    u32 mode = existed ? st.mode : 0644;
    u32 old_uid = existed ? st.uid : edit_uid;
    if (fs_write_as(name, (const u8 *)edit_buf, edit_len, edit_uid, mode) != 0)
        return -1;
    if (existed && old_uid != edit_uid) {
        if (fs_chown_as(name, old_uid, edit_uid) != 0) {
            /* Non-root writer, foreign file: the save stands
               but ownership moved to the writer. Report it. */
            char m[96];
            const char *p = "edit: saved; owner is now ";
            u32 i = 0;
            while (p[i] && i < 60) { m[i] = p[i]; i++; }
            const char *w = users_name_for_uid(edit_uid);
            while (*w && i < 95) m[i++] = *w++;
            m[i] = 0;
            set_msg(m);
            return 1; /* saved, with the owner note */
        }
    }
    return 0;
}
static void do_save_prompt(void) {
    /* Prompt: "File to write: <current>" — the current name
       shows until the user types; Enter with empty input
       saves to the current name, typed text saves as that
       file. An invalid typed name or a failed write reports
       on the status row and returns to editing (buffer kept). */
    char input[32];
    u32 ilen = 0;
    input[0] = 0;
    for (;;) {
        char label[64];
        u32 p = 0;
        const char *t = "File to write: ";
        while (*t) label[p++] = *t++;
        if (ilen == 0) {
            const char *n = edit_name;
            while (*n && p < 60) label[p++] = *n++;
        }
        label[p] = 0;
        render_prompt(label, input);
        int c = wait_key();
        if (c == '\n') break;
        if (c == '\b') {
            if (ilen > 0) input[--ilen] = 0;
            continue;
        }
        if (c >= 32 && c < 127 && ilen < sizeof(input) - 1) {
            input[ilen++] = (char)c;
            input[ilen] = 0;
        }
    }
    const char *target = (ilen == 0) ? edit_name : input;
    if (ilen > 0) {
        /* Typed name must be a valid file name, or the save
           would fail after the user already typed a document. */
        u32 tl = strlen(target);
        int bad = (tl == 0 || tl >= 32);
        for (u32 i = 0; !bad && target[i]; i++) {
            unsigned char ch = (unsigned char)target[i];
            if (ch < 33 || ch > 126 || ch == '/') bad = 1;
        }
        if (bad) { set_msg("edit: bad name"); return; }
    }
    int r = do_save_to(target);
    if (r < 0) { set_msg("edit: cannot save"); return; }
    if (ilen > 0) {
        u32 i = 0;
        while (target[i] && i < 31) { edit_name[i] = target[i]; i++; }
        edit_name[i] = 0;
    }
    edit_modified = 0;
    if (r == 0) {
        char m[64];
        const char *p = "Saved ";
        u32 i = 0;
        while (*p) m[i++] = *p++;
        const char *n = edit_name;
        while (*n && i < 60) m[i++] = *n++;
        m[i] = 0;
        set_msg(m);
    }
    /* Serial marker so tests can observe a save mid-session
       (the screen is invisible to the serial log). */
    serial_write("EDIT-SAVED ");
    serial_write(edit_name);
    serial_write("\n");
}

/* --- open / main loop --- */
static int valid_file_name(const char *name) {
    if (!name || name[0] == 0) return 0;
    u32 len = 0;
    while (name[len]) {
        if (len >= 31) return 0;
        unsigned char ch = (unsigned char)name[len];
        if (ch < 33 || ch > 126 || ch == '/') return 0;
        len++;
    }
    return len > 0;
}

int editor_open(const char *filename, u32 uid) {
    if (!fs_mounted()) { console_write("edit: no filesystem mounted\n"); return -1; }
    if (!valid_file_name(filename)) { console_write("edit: bad name\n"); return -1; }
    edit_uid = uid;
    u32 i = 0;
    while (filename[i] && i < 31) { edit_name[i] = filename[i]; i++; }
    edit_name[i] = 0;
    edit_len = 0;
    edit_buf[0] = 0;
    edit_cy = 0; edit_cx = 0; edit_top = 0;
    edit_modified = 0;
    edit_cut_len = 0;
    edit_cut[0] = 0;
    edit_undo_n = 0;
    edit_redo_n = 0;
    edit_msg[0] = 0;
    /* Load: stat first (permission-checked). Missing file means
       a new empty buffer; an existing but unreadable file is a
       clean refusal before the editor opens. Windows of 1024
       bytes keep the stack small; tabs/CR/controls normalised
       on the way in (see the file header comment). */
    struct fs_stat st;
    if (fs_stat_as(filename, &st, uid) == 0) {
        if (st.size > EDIT_MAX) {
            console_write("edit: file too large (max 131072 bytes)\n");
            return -1;
        }
        u32 off = 0;
        while (off < st.size) {
            u8 win[1024];
            u32 got = 0;
            if (fs_read_range_as(filename, win, sizeof(win), off, &got, uid) != 0 || got == 0)
                break;
            for (u32 j = 0; j < got; j++) {
                u8 ch = win[j];
                if (ch == '\t') {
                    for (int s = 0; s < 4; s++) {
                        if (edit_len >= EDIT_MAX) {
                            console_write("edit: file too large (max 131072 bytes)\n");
                            return -1;
                        }
                        edit_buf[edit_len++] = ' ';
                    }
                } else if (ch == '\r') {
                    continue; /* CRLF -> LF */
                } else if (ch < 32 && ch != '\n') {
                    continue; /* other control bytes dropped */
                } else {
                    if (edit_len >= EDIT_MAX) {
                        console_write("edit: file too large (max 131072 bytes)\n");
                        return -1;
                    }
                    edit_buf[edit_len++] = (char)ch;
                }
            }
            off += got;
        }
        edit_buf[edit_len] = 0;
    } else if (fs_exists(filename)) {
        console_write("edit: cannot read file\n");
        return -1;
    }
    /* Missing file: empty buffer, nothing created until save. */
    for (;;) {
        render();
        int c = wait_key();
        /* Any action key clears a stale status message first
           (the message shows until the next key). */
        if (c != 15 && c != 24) clear_msg();
        switch (c) {
        case 15: /* ^O save */
            do_save_prompt();
            break;
        case 24: /* ^X exit */
            if (!edit_modified) {
                console_clear();
                console_write("edit: done\n");
                return 0;
            }
            render_prompt("Save changes? (y/n/c) ", "");
            {
                int a = wait_key();
                if (a == 'y') {
                    if (do_save_to(edit_name) < 0) {
                        set_msg("edit: cannot save");
                    } else {
                        serial_write("EDIT-SAVED ");
                        serial_write(edit_name);
                        serial_write("\n");
                        console_clear();
                        console_write("edit: done\n");
                        return 0;
                    }
                } else if (a == 'n') {
                    console_clear();
                    console_write("edit: done\n");
                    return 0;
                }
                /* Anything else (incl. 'c') cancels: keep editing. */
                clear_msg();
            }
            break;
        case 23: /* ^W search */
            do_search();
            break;
        case 11: /* ^K cut */
            do_cut();
            break;
        case 21: /* ^U paste */
            do_paste();
            break;
        case 7: /* ^G help */
            do_help();
            break;
        case 26: /* ^Z undo */
            do_undo();
            break;
        case 25: /* ^Y redo */
            do_redo();
            break;
        case KEY_UP:
            if (edit_cy > 0) { edit_cy--; clamp_cursor(); }
            break;
        case KEY_DOWN:
            if (edit_cy + 1 < line_count()) { edit_cy++; clamp_cursor(); }
            break;
        case KEY_LEFT:
            if (edit_cx > 0) edit_cx--;
            else if (edit_cy > 0) { edit_cy--; edit_cx = line_len(edit_cy); }
            break;
        case KEY_RIGHT:
            if (edit_cx < line_len(edit_cy)) edit_cx++;
            else if (edit_cy + 1 < line_count()) { edit_cy++; edit_cx = 0; }
            break;
        case KEY_HOME:
            edit_cx = 0;
            break;
        case KEY_END:
            edit_cx = line_len(edit_cy);
            break;
        case KEY_PGUP:
            edit_cy = (edit_cy >= EDIT_TEXT_ROWS) ? edit_cy - EDIT_TEXT_ROWS : 0;
            clamp_cursor();
            break;
        case KEY_PGDN: {
            u32 lc = line_count();
            edit_cy = (edit_cy + EDIT_TEXT_ROWS < lc) ? edit_cy + EDIT_TEXT_ROWS : lc - 1;
            clamp_cursor();
            break;
        }
        case '\n':
            do_enter();
            break;
        case '\b':
            do_backspace();
            break;
        case KEY_DEL:
            do_delete();
            break;
        default:
            if (c >= 32 && c < 127) do_insert_char((char)c);
            /* Other control codes and PgUp/PgDn (scrollback
               keys, meaningless inside the editor) are ignored. */
            break;
        }
        keep_visible();
    }
}
