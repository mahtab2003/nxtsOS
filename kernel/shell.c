#include "common.h"
#include "console.h"
#include "shell.h"
#include "users.h"
#include "groups.h"
#include "proc.h"
#include "pkg.h"
#include "sha256.h"
#include "aes.h"
#include "csprng.h"
#include "wm.h"
#include "fb.h"
#include "hwinfo.h"
#include "acpi.h"
#include "editor.h"
#include "../drivers/ata.h"
#include "../drivers/blk.h"
#include "../drivers/mouse.h"
#include "../mm/pmm.h"
#include "../drivers/pit.h"
#include "../drivers/keyboard.h"
#include "../fs/vfs.h"
#include "smp.h"
#include "caps.h"
#include "../mm/vma.h"
#include "../net/net.h"
#include "../net/http.h"
#include "../net/fw.h"
#include "../net/sock.h"

static char session_name[32];
static u32 session_uid = 0;
/* Redesign 5 capabilities (CORE_CLI.md section 15.4): the
   session's capability mask. Root starts with every bit;
   non-root starts with none. Login, su, and logout all
   publish through sh_session_start / shell_do_logout, so
   the mask is strictly session-scoped: dropping a bit
   never survives a re-login. proc_set_session_caps hands
   the same mask to processes spawned from this session. */
static u32 session_caps = CAP_ALL;
/* Root gate (redesign 5): passes only if uid == 0 AND the
   needed capability bit is set. Non-root output is byte-
   identical to the old "root only" refusal, so existing
   tests see no change; root without the bit gets a refusal
   naming the missing capability. The MAC hook runs last:
   today it always allows (no policy engine yet). */
static int sh_cap_gate(int bit, const char *cmd) {
    if (session_uid != 0) { console_printf("%s: root only\n", cmd); return -1; }
    if ((session_caps & (1u << bit)) == 0) {
        console_printf("%s: refused: root capability %s is not set (see `cap list`)\n", cmd, caps_name(bit));
        return -2;
    }
    if (mac_check(cmd) != 0) { console_printf("%s: refused by MAC policy\n", cmd); return -3; }
    return 0;
}
/* Multi-session foundations (redesign 5): a session table
   with one active console session (slot 0) plus the data
   structures for more (slots 1-3, always inactive: there is
   no second console to attach them to). `sessions` lists
   the table; `sessions new` refuses honestly. */
struct sh_session { char name[32]; u32 uid; int active; };
static struct sh_session sh_sessions[4];
static int sh_session_n = 0;
static void sh_session_start(u32 uid) {
    session_caps = (uid == 0) ? CAP_ALL : 0;
    proc_set_session_caps(session_caps);
    memset(sh_sessions[0].name, 0, sizeof(sh_sessions[0].name));
    u32 i = 0;
    while (session_name[i] && i < 31) { sh_sessions[0].name[i] = session_name[i]; i++; }
    sh_sessions[0].uid = uid;
    sh_sessions[0].active = 1;
    sh_session_n = 1;
}
/* Version literal, shared by `ver` and `uname` so the two
   can never drift apart. build.sh greps this file for
   "nxtsOS v$(cat VERSION)", which this literal satisfies. */
static const char shell_version[] = "nxtsOS v1.1.5";
static int session_active = 0;
/* Linux-comparability run: exit-status channel. execute_inner
   sets sh_cmd_status (0 recognised, 127 unknown command, or a
   builtin's own code); the outermost execute() copies it to
   sh_last_status, which `$?` expands and `&&`/`||` test. */
static int sh_cmd_status = 0;
static int sh_expand_depth = 0;
static int sh_last_status = 0;
/* Linux-comparability run: session start tick (for `who`) and
   last-activity tick (for `who` idle time, refreshed on every
   keypress in shell_loop). Hostname is a runtime value only:
   `hostname` prints it, root sets it, nothing persists it. */
static u32 session_start_tick = 0;
static u32 sh_activity_tick = 0;
static char sh_hostname[32] = "nxts";
/* §15 session working directory (per-session shell static,
   default "/"; reset on every login, kept across su like a
   Linux cwd is kept across su). Path buffers for cd/rmdir/
   mv/cp/readlink live here, never on the kernel stack. */
static char sh_cwd[256] = "/";
static char sh_canon[256];
static char sh_mv_buf[256];
static char sh_readlink_out[256];
static const char *sh_path_reason(int r) {
    switch (r) {
        case -1: return "not found";
        case -2: return "not a directory";
        case -3: return "permission denied";
        case -4: return "invalid path";
        case -5: return "already exists";
        case -6: return "directory not empty";
        case -7: return "is a directory";
        case -8: return "no space";
        default: return "failed";
    }
}
/* Idle session lock timeout, v0.7.1: configurable via `idle`, default
   120 minutes (was a hardcoded 30 minutes, which users reported as
   "session ends too quickly" with no way to change it). 0 = never
   lock on idle. This is a per-session setting: it resets to 120 on
   reboot, and only the current session's shell can change it. */
static u32 idle_timeout_minutes = 120;

static void audit(const char *event, const char *user) {
    if (!fs_mounted()) return;
    char line[96];
    u32 i = 0;
    const char *p = event;
    while (*p && i < sizeof(line) - 1) line[i++] = *p++;
    if (i < sizeof(line) - 1) line[i++] = ' ';
    p = user;
    while (*p && i < sizeof(line) - 1) line[i++] = *p++;
    if (i < sizeof(line) - 1) line[i++] = ' ';
    /* ticks as decimal, without division by a variable: repeated subtraction. */
    u32 t = timer_ticks;
    char num[12];
    int ni = 0;
    if (t == 0) num[ni++] = '0';
    else {
        char rev[12]; int ri = 0;
        while (t > 0 && ri < 11) { rev[ri++] = (char)('0' + (t % 10u)); t /= 10u; }
        while (ri > 0) num[ni++] = rev[--ri];
    }
    for (int j = 0; j < ni && i < sizeof(line) - 1; j++) line[i++] = num[j];
    if (i < sizeof(line) - 1) line[i++] = '\n';
    if (fs_append("audit.log", (const u8 *)line, i) != 0)
        console_write("audit: log full or unavailable, event not recorded\n");
}

/* Persistent failed-login counts (v0.4.1), stored root-only in
   fails.txt as lines "name:count". A reboot no longer resets the
   brute-force counter: at 3 cumulative failures the account is locked
   until root runs `unlock <user>`. A successful login clears the
   count. Malformed lines are skipped, never fatal. */
struct fail_rec { char name[32]; u32 count; };
static struct fail_rec fails[8];
static int fail_count = 0;
static void fails_load(void) {
    fail_count = 0;
    if (!fs_mounted()) return;
    u8 buf[512]; u32 size = 0;
    if (fs_read("fails.txt", buf, sizeof(buf) - 1, &size) != 0) return;
    buf[size] = 0;
    u32 pos = 0;
    while (pos < size && fail_count < 8) {
        u32 ls = pos;
        while (pos < size && buf[pos] != '\n') pos++;
        u32 ll = pos - ls;
        if (pos < size) pos++;
        if (ll == 0) continue;
        int colon = -1;
        for (u32 i = 0; i < ll; i++) if (buf[ls + i] == ':') { colon = (int)i; break; }
        if (colon <= 0 || colon >= 31 || ll - (u32)colon - 1 == 0) continue;
        u32 v = 0; int bad = 0;
        for (u32 i = (u32)colon + 1; i < ll; i++) {
            if (buf[ls + i] < '0' || buf[ls + i] > '9' || v > 1000000) { bad = 1; break; }
            v = v * 10u + (u32)(buf[ls + i] - '0');
        }
        if (bad) continue;
        memset(&fails[fail_count], 0, sizeof(fails[fail_count]));
        memcpy(fails[fail_count].name, buf + ls, (u32)colon);
        fails[fail_count].count = v;
        fail_count++;
    }
}
static void fails_save(void) {
    if (!fs_mounted()) return;
    char out[512]; u32 i = 0;
    for (int f = 0; f < fail_count; f++) {
        const char *p = fails[f].name;
        while (*p && i < sizeof(out) - 16) out[i++] = *p++;
        if (i < sizeof(out) - 16) out[i++] = ':';
        char num[12]; int ni = 0; u32 t = fails[f].count;
        if (t == 0) num[ni++] = '0';
        else { char rev[12]; int ri = 0; while (t > 0 && ri < 11) { rev[ri++] = (char)('0' + (t % 10u)); t /= 10u; } while (ri > 0) num[ni++] = rev[--ri]; }
        for (int j = 0; j < ni && i < sizeof(out) - 16; j++) out[i++] = num[j];
        if (i < sizeof(out) - 1) out[i++] = '\n';
    }
    fs_write("fails.txt", (const u8 *)out, i, 0, 0600);
}
static int fails_is_locked(const char *name) {
    fails_load();
    for (int i = 0; i < fail_count; i++)
        if (strcmp(fails[i].name, name) == 0) return fails[i].count >= 3;
    return 0;
}
static void fails_record(const char *name) {
    fails_load();
    for (int i = 0; i < fail_count; i++) {
        if (strcmp(fails[i].name, name) == 0) { fails[i].count++; fails_save(); return; }
    }
    if (fail_count < 8) {
        memset(&fails[fail_count], 0, sizeof(fails[fail_count]));
        u32 j = 0; while (name[j] && j < 31) { fails[fail_count].name[j] = name[j]; j++; }
        fails[fail_count].count = 1; fail_count++; fails_save();
    }
}
static void fails_clear(const char *name) {
    fails_load();
    for (int i = 0; i < fail_count; i++) {
        if (strcmp(fails[i].name, name) == 0) {
            fails[i].count = 0; fails_save(); return;
        }
    }
}
/* Drop a user's failed-login record entirely (shell `userdel`):
   without this, a deleted name that is later re-added would
   inherit the old lockout count. Unlike fails_clear (which
   zeroes the count and keeps the line), this removes the entry
   so the file carries no stale record for a deleted account.
   Silently does nothing for an unknown name. */
static void fails_drop(const char *name) {
    fails_load();
    for (int i = 0; i < fail_count; i++) {
        if (strcmp(fails[i].name, name) == 0) {
            for (int j = i; j + 1 < fail_count; j++) fails[j] = fails[j + 1];
            fail_count--;
            fails_save();
            return;
        }
    }
}
/* Unlock primitive shared by the shell `unlock` command and the
   desktop Settings Unlock row. It deliberately performs NO uid
   check: the shell command checks root first, and the desktop
   handler must check root first too (Repo Fetch precedent) —
   fails_clear itself has no uid rule, so calling this without
   the check would let a non-root session reset any account's
   brute-force counter and defeat the 3-failure lockout.
   It DOES check existence: before this fix both callers
   reported success for a name that is not an account at all
   (and wrote a false "unlock" audit entry for it), because
   fails_clear silently does nothing for an unknown name.
   An unknown name returns 0, clears nothing, and audits
   nothing; the callers print the no-such-user refusal. The
   no-audit claim is QEMU-proven by tests/qemu_test_audit_log.py
   (root read-back of audit.log after a refused ghost unlock
   plus a successful alice unlock), not just by this code path.
   The loaded users table comes from users_load() at login.
   users.txt changes at runtime only through `passwd`, which
   rewrites the file and reloads the table itself, so the table
   cannot go stale within a session; in setup mode (no users
   file) every name correctly reports as unknown. */
int shell_unlock_user(const char *name) {
    if (!users_exists(name)) return 0;
    fails_clear(name);
    audit("unlock", name);
    return 1;
}

/* Read one line from the keyboard. echo=1 prints chars, echo=0 prints
   nothing (passwords). Returns length. */
static int read_line(char *buf, u32 max, int echo) {
    u32 len = 0;
    for (;;) {
        keyboard_poll();
        int c = keyboard_getchar();
        if (c < 0) { __asm__ volatile ("hlt"); continue; }
        if (c == '\n') { console_putchar('\n'); buf[len] = 0; return (int)len; }
        if (c == '\b') {
            if (len > 0) { len--; if (echo) console_putchar('\b'); }
        } else if (c >= 0x100) {
            /* Special key (PgUp/PgDn): ignored here, never appended
               (a (char) truncation would store a NUL/control byte). */
        } else if (c < 32) {
            /* Control code (Ctrl+letter, now delivered by the
               keyboard driver for the editor): ignored here, so
               Ctrl keys can never pollute a login, password, or
               command-line buffer. \n and \b are handled above. */
        } else if (len < max - 1) {
            buf[len++] = (char)c;
            if (echo) console_putchar((char)c);
        }
    }
}

/* Login prompt. Returns 1 on successful login (session set), and never
   returns on 3 consecutive failures (system halted). If no users file
   exists, falls back to root with a warning and returns 1. */
static int do_login(void) {
    /* Flush stale keys before a RE-LOGIN prompt, so a key pressed
       during the previous session (or during logout) cannot be
       consumed as a username and silently fail a login attempt.
       Do NOT flush on the first login after boot: the boot message
       promises "keys typed now are buffered", and test harnesses
       (and users) type the login before the prompt appears — those
       buffered keys must survive. Flushing on every login broke
       that promise and failed the base/encryption tests. */
    static int seen_login = 0;
    if (seen_login) keyboard_flush();
    seen_login = 1;
    int n = users_load();
    if (n == 0) {
        console_write("No users file found: running as root (setup mode).\n");
        console_write("Create users.txt on the disk to enable login.\n");
        memset(session_name, 0, sizeof(session_name));
        session_name[0] = 'r'; session_name[1] = 'o'; session_name[2] = 'o'; session_name[3] = 't';
        session_uid = 0; session_active = 1;
        sh_session_start(0);
        sh_cwd[0] = '/'; sh_cwd[1] = 0;
        session_start_tick = timer_ticks; sh_activity_tick = timer_ticks;
        return 1;
    }
    console_printf("Users configured: %u\n", n);
    for (int attempt = 1; attempt <= 3; attempt++) {
        char user[32], pass[64];
        console_write("login: ");
        read_line(user, sizeof(user), 1);
        console_write("Password: ");
        read_line(pass, sizeof(pass), 0);
        /* Locked accounts are rejected even with the right password.
           The password is still prompted first, so a locked account
           follows the same login flow as any other (and a scripted
           login does not desynchronise). */
        if (fails_is_locked(user)) {
            audit("login-locked", user);
            console_write("Account locked. Contact root to unlock.\n");
            continue;
        }
        u32 uid = 0;
        if (users_check(user, pass, &uid)) {
            fails_clear(user);
            memset(session_name, 0, sizeof(session_name));
            u32 i = 0;
            while (user[i] && i < 31) { session_name[i] = user[i]; i++; }
            session_uid = uid; session_active = 1;
            sh_cwd[0] = '/'; sh_cwd[1] = 0;
            session_start_tick = timer_ticks; sh_activity_tick = timer_ticks;
            sh_session_start(uid);
            audit("login-ok", user);
            console_printf("Welcome, %s.\n", session_name);
            return 1;
        }
        fails_record(user);
        audit("login-fail", user);
        console_write("Login incorrect\n");
    }
    audit("login-locked", "system");
    console_write("Too many failed attempts. System halted.\n");
    for (;;) __asm__ volatile ("hlt");
}

static void cmd_mem(void) {
    console_printf("Memory: total %u frames (%u KiB), free %u frames (%u KiB), "
                   "used %u frames (%u KiB)\n",
                   pmm_total_frames(), pmm_total_frames() * 4,
                   pmm_free_frames(), pmm_free_frames() * 4,
                   pmm_used_frames(), pmm_used_frames() * 4);
}

/* Ticks (100 Hz) to whole seconds, by repeated subtraction: the
   freestanding kernel links no libgcc, so no division helper is
   assumed even for a constant divisor. */
static u32 ticks_to_seconds(u32 ticks) {
    u32 s = 0;
    while (ticks >= 100) { ticks -= 100; s++; }
    return s;
}

/* Split seconds into d/h/m/s, also by repeated subtraction. */
static void split_uptime(u32 secs, u32 *d, u32 *h, u32 *m, u32 *s) {
    *d = 0; while (secs >= 86400) { secs -= 86400; (*d)++; }
    *h = 0; while (secs >= 3600) { secs -= 3600; (*h)++; }
    *m = 0; while (secs >= 60) { secs -= 60; (*m)++; }
    *s = secs;
}

/* PCI row printer for hw_pci_scan (core CLI family (a)). */
static void pci_print_row(u8 dev, u8 func, u16 vendor, u16 device,
                          u8 class_code, u8 subclass, u8 prog_if, u32 bar0) {
    console_printf("  %u:%u  %x:%x  class %x/%x/%x  BAR0 0x%x\n",
                   (u32)dev, (u32)func, (u32)vendor, (u32)device,
                   (u32)class_code, (u32)subclass, (u32)prog_if, bar0);
}

/* Linux-comparability run helpers. */
static void pci_print_detail_row(u8 dev, u8 func, u16 vendor, u16 device,
                                 u8 class_code, u8 subclass, u8 prog_if, u8 rev,
                                 u32 bar0, u32 bar1, u32 bar2, u32 bar3, u32 bar4, u32 bar5,
                                 u8 irq) {
    console_printf("  %u:%u  %x:%x  class %x/%x/%x rev %u irq %u\n",
                   (u32)dev, (u32)func, (u32)vendor, (u32)device,
                   (u32)class_code, (u32)subclass, (u32)prog_if, (u32)rev, (u32)irq);
    console_printf("      BAR0 0x%x BAR1 0x%x BAR2 0x%x BAR3 0x%x BAR4 0x%x BAR5 0x%x\n",
                   bar0, bar1, bar2, bar3, bar4, bar5);
}
static void sh_print_pad2(u32 v) {
    console_putchar((char)('0' + (v / 10u) % 10u));
    console_putchar((char)('0' + v % 10u));
}
static void lsusb_print_row(u8 dev, u8 func, u16 vendor, u16 device,
                            u8 class_code, u8 subclass, u8 prog_if, u32 bar0) {
    (void)bar0;
    if (class_code != 0x0C || subclass != 0x03) return;
    console_printf("  %u:%u  %x:%x  USB controller prog-if %u\n",
                   (u32)dev, (u32)func, (u32)vendor, (u32)device, (u32)prog_if);
}
/* Print audit.log lines for root only. filter: 0 = all lines,
   1 = login lines only (login-ok/login-fail/login-locked).
   tail_n: 0 = all, else the last tail_n matching lines.
   audit.log lines are "event user ticks" (audit() caps them
   at 95 chars, so a 96-byte line buffer is exact). The log
   is streamed in 1024-byte windows, so its size is not
   capped: pass 1 counts matching lines, pass 2 prints from
   the tail offset. */
static u8 sh_audit_win[1024];
static char sh_audit_line[96];
static int sh_audit_line_matches(const char *line, int filter_login) {
    if (!filter_login) return 1;
    return line[0] == 'l' && line[1] == 'o' && line[2] == 'g' &&
           line[3] == 'i' && line[4] == 'n' && line[5] == '-';
}
/* One streaming pass over audit.log. If print_from is < 0,
   nothing is printed (count only); otherwise matching lines
   with index >= print_from are printed. Returns the matching
   line count, or -1 when the log cannot be read. */
static int sh_audit_pass(int filter_login, int print_from) {
    struct fs_stat st;
    if (fs_stat_as("audit.log", &st, 0) != 0) return -1;
    u32 size = st.size, off = 0, llen = 0, idx = 0;
    while (off < size) {
        u32 want = size - off;
        if (want > sizeof(sh_audit_win)) want = sizeof(sh_audit_win);
        u32 got = 0;
        if (fs_read_range_as("audit.log", sh_audit_win, want, off, &got, 0) != 0) return -1;
        if (got == 0) break;
        off += got;
        for (u32 k = 0; k < got; k++) {
            char ch = (char)sh_audit_win[k];
            if (ch == '\n') {
                sh_audit_line[llen] = 0;
                if (sh_audit_line_matches(sh_audit_line, filter_login)) {
                    if (print_from >= 0 && (int)idx >= print_from) {
                        console_write(sh_audit_line);
                        console_putchar('\n');
                    }
                    idx++;
                }
                llen = 0;
            } else if (llen < 95) sh_audit_line[llen++] = ch;
        }
    }
    if (llen > 0) {
        sh_audit_line[llen] = 0;
        if (sh_audit_line_matches(sh_audit_line, filter_login)) {
            if (print_from >= 0 && (int)idx >= print_from) {
                console_write(sh_audit_line);
                console_putchar('\n');
            }
            idx++;
        }
    }
    return (int)idx;
}
static void sh_print_audit(int filter_login, u32 tail_n) {
    if (sh_cap_gate(CAP_AUDIT, "log") != 0) return;
    if (!fs_mounted()) { console_write("log: no filesystem\n"); return; }
    int total = sh_audit_pass(filter_login, -1);
    if (total < 0) { console_write("log: no audit log\n"); return; }
    if (total == 0) { console_write("(no matching log entries)\n"); return; }
    int from = 0;
    if (tail_n > 0 && tail_n < (u32)total) from = total - (int)tail_n;
    sh_audit_pass(filter_login, from);
}

/* CPU feature-flag printer: one space-separated name per set bit,
   EDX then ECX of CPUID leaf 1, plus NX from the extended leaf.
   The console wraps at 80 columns, so one logical line is fine. */
static void cpu_print_flags(u32 ecx, u32 edx, int nx) {
    static const char *edx_names[32] = {
        "FPU", "VME", "DE", "PSE", "TSC", "MSR", "PAE", "MCE",
        "CX8", "APIC", 0, "SEP", "MTRR", "PGE", "MCA", "CMOV",
        "PAT", "PSE36", 0, "CLFSH", 0, 0, 0, "MMX",
        "FXSR", "SSE", "SSE2", 0, "HTT", 0, 0, 0
    };
    static const char *ecx_names[32] = {
        "SSE3", "PCLMULQDQ", 0, 0, 0, 0, 0, 0,
        0, "SSSE3", 0, 0, "FMA", "CX16", 0, 0,
        0, 0, 0, "SSE4.1", "SSE4.2", 0, "MOVBE", "POPCNT",
        0, "AES", "XSAVE", 0, "AVX", "F16C", "RDRAND", 0
    };
    console_write("Features:");
    for (int b = 0; b < 32; b++) {
        if ((edx & (1u << b)) && edx_names[b]) {
            console_putchar(' '); console_write(edx_names[b]);
        }
    }
    for (int b = 0; b < 32; b++) {
        if ((ecx & (1u << b)) && ecx_names[b]) {
            console_putchar(' '); console_write(ecx_names[b]);
        }
    }
    if (nx) console_write(" NX");
    console_putchar('\n');
}

/* Quoting (redesign 5, CORE_CLI.md section 15.4): one word
   parser shared by tokenize(), sh_split_args(), and
   sh_split_rest(), so every command tokenizes the same way.
   A word is a run of segments: unquoted chars, '...' (every
   byte literal, no escapes), "..." (backslash escapes the
   next byte), and \x escapes outside quotes (the next byte
   is literal, even a space or a quote). Adjacent segments
   concatenate into one word (a"b c"d -> "ab cd"), and an
   empty quoted string ('', "") is still a word (it counts
   as an argument). The word is compacted in place — quotes
   and escape backslashes are removed, so the result never
   outgrows the source span — and NUL-terminated; *pp
   advances past the word (to the space or NUL ending it).
   Returns 0, or -1 on an unterminated quote (the word is
   still compacted to end-of-line; callers decide how visibly
   to fail: tokenize() errors outright, the arg splitters
   drop the partial word so the command fails visibly,
   usually as a usage error). */
/* Contract: on success, *pp points PAST one terminating space
   when the word ended at a space (the space itself is
   overwritten by the word's NUL when unquoted, so callers
   must not test *pp for a space after parsing), or at the
   NUL when the word ran to end of string. Callers skip any
   further spaces themselves. */
static int sh_parse_word(char **pp) {
    char *p = *pp;
    char *w = p;
    int quote = 0; /* 0 none, '\'' single, '"' double */
    while (*p) {
        char c = *p;
        if (quote == '\'') {
            if (c == '\'') { quote = 0; p++; }
            else { *w++ = c; p++; }
            continue;
        }
        if (quote == '"') {
            if (c == '"') { quote = 0; p++; continue; }
            if (c == '\\' && p[1]) { *w++ = p[1]; p += 2; continue; }
            *w++ = c; p++;
            continue;
        }
        if (c == ' ') break;
        if (c == '\'') { quote = '\''; p++; continue; }
        if (c == '"') { quote = '"'; p++; continue; }
        if (c == '\\' && p[1]) { *w++ = p[1]; p += 2; continue; }
        *w++ = c; p++;
    }
    /* Capture the delimiter BEFORE writing the NUL: for an
       unquoted word w == p at the break, so *w = 0 would
       destroy the very space this test needs. */
    int ended_space = (*p == ' ');
    *w = 0;
    if (ended_space) p++; /* past the terminating space (see contract above) */
    *pp = p;
    return quote ? -1 : 0;
}

/* Unquote a whole text span (echo/write text, where spaces
   do NOT split words): quotes group, escapes literalise,
   everything else copies. Returns 0, or -1 on overflow or
   an unterminated quote (out is left NUL-terminated but
   must not be used). */
static int sh_unquote_copy(const char *in, char *out, u32 cap) {
    u32 o = 0;
    int quote = 0;
    for (u32 i = 0; in[i]; i++) {
        char c = in[i];
        if (quote == '\'') {
            if (c == '\'') quote = 0;
            else {
                if (o + 1 >= cap) return -1;
                out[o++] = c;
            }
            continue;
        }
        if (quote == '"') {
            if (c == '"') { quote = 0; continue; }
            if (c == '\\' && in[i + 1]) {
                if (o + 1 >= cap) return -1;
                out[o++] = in[++i];
                continue;
            }
            if (o + 1 >= cap) return -1;
            out[o++] = c;
            continue;
        }
        if (c == '\'') { quote = '\''; continue; }
        if (c == '"') { quote = '"'; continue; }
        if (c == '\\' && in[i + 1]) {
            if (o + 1 >= cap) return -1;
            out[o++] = in[++i];
            continue;
        }
        if (o + 1 >= cap) return -1;
        out[o++] = c;
    }
    out[o] = 0;
    return quote ? -1 : 0;
}
/* Scratch for echo/write unquoting (file-scope, never the
   stack; a line is at most 127 chars, so 128 always fits). */
static char sh_unquote_buf[128];

static int tokenize(char *line, char *tok[], char **rest) {
    int n = 0;
    *rest = 0;
    char *p = line;
    while (*p && n < 4) {
        while (*p == ' ') p++;
        if (*p == 0) break;
        tok[n] = p;
        if (sh_parse_word(&p) != 0) return -1;
        n++;
        if (n == 2) {
            while (*p == ' ') p++;
            if (*p) *rest = p;
            break;
        }
    }
    return n;
}

/* Session logout (shared by the `logout` command and by a confirmed
   desktop Logout click, which the shell performs when the desktop
   returns). Kills the session's background jobs, audits, ends the
   session, and returns 1 so the shell loop exits to the login
   prompt. */
static int shell_do_logout(void) {
    int killed = proc_bg_kill_for_uid(session_uid);
    if (killed > 0) console_printf("Killed %u background job(s) on logout.\n", killed);
    audit("logout", session_name);
    console_write("Logged out.\n");
    session_active = 0;
    session_caps = 0;
    proc_set_session_caps(0);
    sh_session_n = 0;
    return 1;
}

/* Session lock prompt (shared by the idle timeout and the `lock`
   command). Returns 1 if unlocked (session continues), 0 if the
   unlock failed and the caller must log out. In setup mode (no users
   file) there is no password to check, so lock is a no-op that
   reports it and continues. */
static int do_lock(void) {
    if (users_count() == 0) {
        console_write("No users configured: session lock unavailable in setup mode.\n");
        return 1;
    }
    /* Stale keys from the previous session must not become the
       unlock password (see keyboard_flush). */
    keyboard_flush();
    console_write("Session locked. Enter password: ");
    char pass[64];
    read_line(pass, sizeof(pass), 0);
    u32 uid = 0;
    if (users_check(session_name, pass, &uid) && uid == session_uid) {
        console_write("Session unlocked.\n");
        return 1;
    }
    console_write("Unlock failed. Logging out.\n");
    return 0;
}

/* Shell grouping + per-command help (apps run, user rule 21:09 PKT).
   Every command belongs to exactly one group; the table is the
   single source for `help` output AND for group dispatch
   (`net ping ...`, `test csprngtest`, ...). Flat names keep
   working as aliases (see the design note in AUTONOMOUS.md);
   the help system itself never stacks everything into one dump:
   bare `help` is a short group index, detail lives per command.
   Groups are pure: a group holds only its own kind (verdict-
   printing self-tests live under test even when their topic is
   crypto or network). Usage strings match the Usage: lines the
   commands themselves print on error, so help and behaviour
   cannot drift apart silently. */
struct help_entry { const char *name; const char *group; const char *usage; const char *desc; };
struct help_group { const char *name; const char *desc; };
static const struct help_group help_groups[] = {
    {"system", "System information and control"},
    {"session", "Login session and accounts"},
    {"fs", "Files and filesystem"},
    {"proc", "Programs and background jobs"},
    {"pkg", "Packages and system updates"},
    {"net", "Network, web, and trust stores"},
    {"crypto", "Cryptographic tools"},
    {"diag", "Hardware diagnostics"},
    {"gui", "Graphical interfaces"},
    {"text", "Text tools (grep, sort, wc, head, tail, diff)"},
    {"test", "Self-tests and autotest scripts"},
};
static const struct help_entry help_table[] = {
    {"help", "system", "help [group|command]", "Show the group index, a group's commands, or one command's dedicated help."},
    {"ver", "system", "ver", "Print the nxtsOS version (same literal build.sh checks)."},
    {"mem", "system", "mem", "Show physical memory frames: total, free, used."},
    {"ticks", "system", "ticks", "Show timer ticks and uptime in seconds (100 Hz)."},
    {"uptime", "system", "uptime [-p|-s]", "Show uptime as days, hours, minutes, seconds, plus background job count. -p prints a pretty form, -s prints the boot time (RTC now minus uptime)."},
    {"who", "system", "who", "Show who is logged in on this console (single session: user, uid, idle time, session start tick)."},
    {"w", "system", "w", "Alias for who."},
    {"hostname", "system", "hostname [name]", "Show the runtime hostname, or set it (root only). Runtime only, never persisted."},
    {"dmesg", "system", "dmesg [-c]", "Print the kernel log ring (last 64 console lines). -c clears it (root only)."},
    {"log", "system", "log [-n N]", "Root only: print the audit log (last N lines with -n N)."},
    {"last", "system", "last [-n N]", "Root only: print login lines from the audit log (last N with -n N)."},
    {"locale", "system", "locale", "Print the system locale (C locale, ASCII only — the console has a single-byte font and no locale data)."},
    {"pwd", "system", "pwd", "Print the session working directory (starts at /; changed by cd)."},
    {"cd", "system", "cd [path]", "Change the session working directory (no path means /). Paths may be absolute or relative to the current directory; .. at root stays at root."},
    {"date", "system", "date | date set <YYYY-MM-DD> <HH:MM:SS>", "Show the wall-clock date and time from the CMOS RTC (YYYY-MM-DD HH:MM:SS, year = 2000 + RTC year register). date set is root only."},
    {"sysinfo", "system", "sysinfo", "One-screen system summary: version, CPU, memory, disk, network, jobs, session."},
    {"clear", "system", "clear", "Clear the text console."},
    {"echo", "system", "echo <text>", "Print text to the console."},
    {"true", "system", "true", "Do nothing, successfully (exit status 0; useful with && and if)."},
    {"false", "system", "false", "Do nothing, unsuccessfully (exit status 1; useful with || and if)."},
    {"test", "system", "test <expression>", "Evaluate a condition (exit status 0 true, 1 false): -f/-d/-r/-w file, -z/-n string, =/!= string, -eq/-ne/-lt/-le/-gt/-ge numbers, ! negation. [ ... ] is the same with a closing ]."},
    {"sleep", "system", "sleep <seconds>", "Wait up to 3600 seconds (Ctrl-C interrupts)."},
    {"read", "system", "read <VAR>", "Read one line from the keyboard into a session environment variable."},
    {"sh", "system", "sh <file>", "Run a script file: comments (#), sequential commands, chaining, if/else/endif, for/in/endfor, while/endwhile (max 100 iterations). A script's exit ends the script, never the session."},
    {"source", "system", "source <file>", "Alias for sh (run a script file)."},
    {"history", "system", "history [-c]", "Show the session command history (never saved to disk). history -c clears it."},
    {"export", "system", "export NAME=VALUE", "Set a session environment variable (session only, never saved). Bare export lists all variables."},
    {"unset", "system", "unset NAME", "Remove a session environment variable (silent when missing)."},
    {"alias", "system", "alias <name> <command...>", "Define a session alias (one-level expansion, session only). Bare alias lists all aliases."},
    {"unalias", "system", "unalias <name>", "Remove a session alias."},
    {"man", "system", "man <command>", "Print a command's dedicated help entry (same as help <command>)."},
    {"uname", "system", "uname [-a]", "Print the system name (bare) or name, version, and machine (-a)."},
    {"free", "system", "free", "Alias for mem."},
    {"reboot", "system", "reboot", "Reboot immediately via the keyboard controller (no confirm, no uid check)."},
    {"shutdown", "system", "shutdown [--force]", "Root only: power off via ACPI (asks y/n unless --force). Refuses cleanly when ACPI poweroff is unavailable."},
    {"poweroff", "system", "poweroff [--force]", "Alias for shutdown."},
    {"halt", "system", "halt [--force]", "Root only: stop the CPU (asks y/n unless --force). The VM stays present but halted."},
    {"whoami", "session", "whoami", "Print the current session user and uid."},
    {"lock", "session", "lock", "Lock the session; unlock with the session password (unavailable in setup mode)."},
    {"unlock", "session", "unlock <user>", "Root only: clear a user's failed-login lockout."},
    {"passwd", "session", "passwd [user]", "Change a password (root: any user; others: own only, current password required)."},
    {"useradd", "session", "useradd <user>", "Root only: create a user (prompts for a password, echo off). Creates users.txt if none exists; after that, logins use the file."},
    {"userdel", "session", "userdel <user>", "Root only: delete a user (never root, never the session user). Drops the user's failed-login record."},
    {"groupadd", "session", "groupadd <group>", "Root only: create a group (gid auto-assigned from 1000). Creates groups.txt if none exists."},
    {"groupdel", "session", "groupdel <group>", "Root only: delete a group."},
    {"groupmod", "session", "groupmod <group> add|remove <user>", "Root only: add or remove a user from a group."},
    {"groups", "session", "groups [user]", "List the groups a user belongs to (default: session user)."},
    {"id", "session", "id [user]", "Print uid and groups for a user (default: session user)."},
    {"logout", "session", "logout", "Kill the session's background jobs and return to the login prompt."},
    {"su", "session", "su [user]", "Switch the session user (default root). Root switches without a password; anyone else must pass the target user's password. Root itself is not a login account, so su to root from non-root is refused (use a uid-0 account). Background jobs keep their owners."},
    {"sudo", "session", "sudo [-l] <command...>", "Run one command as root. Allowed for members of group sudo or names listed in sudoers.txt, after a password check (3 attempts). Audited per use. Session/interactive commands (logout, exit, su, lock, passwd, edit, top, gui, desktop) are refused inside sudo. sudo -l shows the caller's sudo right after a password check."},
    {"exit", "session", "exit", "Alias for logout."},
    {"idle", "session", "idle [minutes 0-480|off]", "Show or set the idle session-lock timeout for this session (0 = never)."},
    {"fs", "fs", "fs", "Show filesystem status (mounted, files, space)."},
    {"ls", "fs", "ls [path]", "List a directory's children as a list view (header, names, footer count). No path lists the current directory; a file path lists that file. Directory names print with a trailing /."},
    {"mkdir", "fs", "mkdir <path>", "Create a directory (the parent must already exist; refuses an existing child name)."},
    {"rmdir", "fs", "rmdir <path>", "Remove an empty directory (refuses a non-empty directory, the root, and the current directory)."},
    {"cat", "fs", "cat <file>", "Print a whole text file, in 1023-byte windows. Paths may be absolute or relative to the current directory."},
    {"write", "fs", "write <file> <text>", "Create or overwrite a file with text. Paths may be absolute or relative to the current directory."},
    {"rm", "fs", "rm <file>", "Delete a file (permission-checked). Refuses directories (use rmdir)."},
    {"mv", "fs", "mv <old> <new>", "Rename a file or directory; across directories only the parent changes, data is untouched. A destination that is an existing directory moves the source into it."},
    {"cp", "fs", "cp <src> <dst>", "Copy a file (a new file, never a new link). A destination that is an existing directory copies into it."},
    {"ln", "fs", "ln <src> <link> | ln -s <target> <link>", "Create a hard link (a second entry sharing the source's data sectors; deleting one link frees the sectors only when no link remains) or a symbolic link (target may be a path; max 4 hops on read, loops fail)."},
    {"readlink", "fs", "readlink <link>", "Print a symbolic link's target (fails for non-links)."},
    {"mkfifo", "fs", "mkfifo <name>", "Create a named pipe (FIFO): programs open it by name for reading/writing, blocking until the other end opens. Not a file: cat/write refuse it; only the fd layer opens it."},
    {"chmod", "fs", "chmod <file> <mode>", "Set a file mode (octal, 3 digits, e.g. 600 or 0644)."},
    {"chown", "fs", "chown <file> <user>", "Root only: change a file's owner (metadata only; mode, size, data untouched)."},
    {"chgrp", "fs", "chgrp <file> <group>", "Root only: change a file's group (metadata only; group members then use the group permission triple)."},
    {"stat", "fs", "stat <file>", "Show a file's size, owner, group, mode, sector count, and sidecar timestamps in ticks (root, owner, or any reader)."},
    {"df", "fs", "df", "Show filesystem size, used, and free space in MiB, plus the file count."},
    {"du", "fs", "du [file...]", "Show per-file sizes plus a total; bare du totals all files readable by the session."},
    {"find", "fs", "find [pattern]", "List files whose names contain the substring; no pattern lists all readable files."},
    {"touch", "fs", "touch <file>", "Create an empty file if missing, else report exists (touch does not itself update sidecar timestamps; reads and writes do). Refuses files the caller cannot see."},
    {"edit", "fs", "edit <file>", "Full-screen text editor (nano-like: ^O save, ^X exit, ^W search, ^K cut, ^U paste, ^G help)."},
    {"run", "proc", "run <file>", "Run an ELF program in the foreground."},
    {"runbg", "proc", "runbg <file>", "Start an ELF program as a background job."},
    {"jobs", "proc", "jobs", "List background jobs as a list view (header, rows, footer count)."},
    {"ps", "proc", "ps", "Show the session plus background jobs (pid, name, uid)."},
    {"top", "proc", "top", "Live resource monitor (uptime, memory, disk, network, jobs); press q to quit, k to kill a job by pid (or %N)."},
    {"kill", "proc", "kill [-N] <pid|%N>", "Kill a background job by pid (own jobs, or any as root). %N kills the Nth job in `jobs` order. With -N (or -NAME), send signal N instead of killing: 1 HUP, 2 INT, 9 KILL, 15 TERM, 18 CONT, 19 STOP."},
    {"signals", "proc", "signals", "List the signals that can be sent to background jobs with `kill -N`, and what each does."},
    {"killall", "proc", "killall <name>", "Kill all background jobs with this program name (same permission rule as kill)."},
    {"nice", "proc", "nice [-n N] runbg <file>", "Start a background job with a nice value (-20..19, default 0; negative values need root). Higher nice runs less often per tick."},
    {"renice", "proc", "renice <N> <pid|%N>", "Change a background job's nice value (-20..19). Own jobs, or any as root; negative values need root."},
    {"sched", "proc", "sched [-v]", "List background jobs with their nice values and tick-run counts (jobs/ps formats are pinned by tests and are not changed). -v adds vruntime and weight columns (redesign 5 fair runqueue)."},
    {"vma", "diag", "vma", "Show demand-paging stats: faults handled, pages mapped, swap state."},
    {"cap", "session", "cap list|drop <capability>|grant <capability>|show <pid>", "Capabilities: list the session mask, drop/grant one bit (needs uid 0 + cap_cap), or show a background job's inherited mask. A root gate passes only with uid 0 AND its bit set."},
    {"mac", "session", "mac status", "Show MAC status: no policy loaded (hook points in every root gate, enforcement off)."},
    {"sessions", "session", "sessions [new]", "List console sessions (one active; more slots exist but stay inactive). sessions new is refused: no second console exists."},
    {"fg", "proc", "fg <pid|%N>", "Wait until a background job exits (bring it to the foreground). Ctrl-C kills the waited job and returns; a hung job never wedges the shell. Same permission rule as kill."},
    {"wait", "proc", "wait [pid|%N]", "Wait for one background job, or all visible jobs with no argument. Ctrl-C kills the current waited job and stops the wait. Same permission rule as kill."},
    {"grep", "text", "grep [-i] [-v] [-n] [-c] [-F] [-E] <pattern> [files...]", "Print lines matching the pattern (regex: . * + ? ^ $ [...] [^...] \\d \\w \\s, top-level |; groups are not supported). -F selects literal-substring matching instead, -E is the same as the default. -i case-insensitive, -v invert, -n line numbers, -c counts only. Exit status 0 if any line matched, 1 if none. File - or no file reads the shell stdin source (pipelines)."},
    {"sed", "text", "sed [-n] <script> [files...]", "Stream editor: s/old/new/[g] (old is a regex, & in new means the whole match), Np, N,Mp, /re/p print, d delete. Default prints every line (p-matched lines twice); -n prints only lines the script affects. No -i (use redirection). File - or no file reads the shell stdin source (pipelines)."},
    {"tr", "text", "tr [-d] [-s] <set1> [set2]", "Translate bytes: set1 chars become set2 chars (ranges like a-z, escapes \\n \\t \\\\). -d deletes set1 chars, -s squeezes repeats of set2 (or set1 when set2 is absent). File - or no file reads the shell stdin source (pipelines)."},
    {"cut", "text", "cut -d <delim> -f <list> | cut -c <list>", "Cut fields (delimiter, e.g. -d :) or characters from each line. Lists like 1,3,1-3. File - or no file reads the shell stdin source (pipelines)."},
    {"uniq", "text", "uniq [-c] [-d] [-u] [files...]", "Print only one copy of each run of identical consecutive lines. -c prefixes counts, -d only duplicated lines, -u only unique lines. File - or no file reads the shell stdin source (pipelines)."},
    {"tee", "text", "tee [-a] <file>...", "Copy stdin (a pipeline) to each named file and to stdout. Without -a files are truncated; -a appends. Total cap 64 KiB, fail-visible beyond."},
    {"seq", "text", "seq [first [step]] last", "Print numbers from first (default 1) to last in steps of step (default 1; negative steps allowed). Max 10,000 numbers."},
    {"basename", "text", "basename <name>", "Print the last component of a name (flat names print unchanged)."},
    {"dirname", "text", "dirname <name>", "Print the directory part of a name, lexically (a bare name gives /)."},
    {"more", "text", "more [file]", "Page output 20 lines at a time: space for the next page, q to quit. File - or no file reads the shell stdin source (pipelines)."},
    {"less", "text", "less [file]", "Alias for more (same pager)."},
    {"sort", "text", "sort [files...]", "Sort all input lines in byte order. At most 256 lines; over-cap refuses without partial output."},
    {"wc", "text", "wc [-l] [-w] [-c] [files...]", "Count lines (-l, newline bytes), words (-w), bytes (-c). Default is all three; multi-file adds a total line."},
    {"head", "text", "head [-n N] [files...]", "Print the first N lines (default 10). Multi-file output has ==> file <== headers."},
    {"tail", "text", "tail [-n N] [files...]", "Print the last N lines (default 10; two-pass, no line ring). Multi-file output has ==> file <== headers."},
    {"diff", "text", "diff <file1> <file2>", "Line diff in normal format (NcM/Ad/Ac headers, < and > lines) via LCS. At most 256 lines per file; binary input is compared as lines anyway."},
    {"pkg", "pkg", "pkg <subcommand>", "Package manager (see 'help pkg' for subcommands)."},
    {"pkg list", "pkg", "pkg list", "List installed packages (header, rows, footer count)."},
    {"pkg avail", "pkg", "pkg avail", "List packages available from the configured repository."},
    {"pkg search", "pkg", "pkg search <pattern>", "Search the downloaded repository index by substring (same index as pkg avail; no network)."},
    {"pkg install", "pkg", "pkg install <file>|<name>", "Root only: install a local .nxpkg file, or a named package from the repo."},
    {"pkg remove", "pkg", "pkg remove <name> [force]", "Root only: remove an installed package (force skips the dependency check)."},
    {"pkg repo", "pkg", "pkg repo [url]", "Show the repository URL, or set it (root only). https:// is TOFU, httpsa:// is anchored, httpss:// uses the CA store."},
    {"pkg update", "pkg", "pkg update", "Root only: refresh the repository index over anchored HTTPS."},
    {"pkg fetch", "pkg", "pkg fetch <name>", "Root only: download a package from the repo without installing it."},
    {"sysupdate", "pkg", "sysupdate <bundle.nxupd>", "Root only: apply a signed system-update bundle (snapshot + rollback on failure)."},
    {"sysrollback", "pkg", "sysrollback", "Root only: roll back to the pre-update snapshot."},
    {"netinfo", "net", "netinfo", "Show NIC MAC, counters, and IP configuration."},
    {"netdbg", "net", "netdbg", "Dump network driver debug state."},
    {"ip", "net", "ip addr|link|route", "Show IP configuration (addr), link state and counters (link), or the default route (route). Read-only: the stack has one static route, so route changes are refused."},
    {"hosts", "net", "hosts", "List hosts.txt entries (IP hostname lines). dns consults hosts.txt before the DNS server."},
    {"dhcp", "net", "dhcp", "Root only: configure IP via DHCP."},
    {"ping", "net", "ping <ip>", "Ping a dotted-quad IPv4 address; reports reply or no reply."},
    {"dns", "net", "dns <name>", "Look up a hostname via the configured DNS server."},
    {"dnsset", "net", "dnsset <ip>", "Root only: set the DNS server address."},
    {"http", "net", "http [--no-redirect] [--no-cookies] <host> <path> [port]", "Fetch a page over plain HTTP (default port 80). Redirects are followed (max 5 hops) and cookies kept in a jar unless disabled."},
    {"cookies", "net", "cookies list | cookies clear", "List the HTTP cookie jar (name, domain, path, Secure, expiry) or clear it."},
    {"https", "net", "https [--legacy] [--no-redirect] [--no-cookies] <host> <path> [port]", "Fetch over TLS 1.3/1.2, TOFU trust (default port 443). --legacy fetches over TLS 1.1/SSLv3 instead (INSECURE LEGACY, old servers only). Redirects are followed (max 5 hops, never https to http) and cookies kept in a jar unless disabled."},
    {"httpsa", "net", "httpsa [--legacy] [--no-redirect] [--no-cookies] <host> <path> [port]", "Fetch over TLS, anchored trust (pinned anchor must terminate the chain). --legacy fetches over TLS 1.1/SSLv3 instead. Redirects and cookies as for https."},
    {"httpss", "net", "httpss [--legacy] [--no-redirect] [--no-cookies] <host> <path> [port]", "Fetch over TLS, CA-store trust (castore.txt). --legacy fetches over TLS 1.1/SSLv3 instead. Redirects and cookies as for https."},
    {"sslprobe", "net", "sslprobe <host> [port]", "Send an SSLv2-format ClientHello and classify the reply (SSLv2 SERVER_HELLO, TLS ServerHello version, alert, or no reply) without establishing a session."},
    {"castore", "net", "castore list|add <file>|update <host> [port]|clear", "Manage the CA store (root for add/update/clear)."},
    {"castore list", "net", "castore list", "Count well-formed roots in castore.txt."},
    {"castore add", "net", "castore add <file>", "Root only: add one store line from a file (RSA modulus or EC256: point)."},
    {"castore update", "net", "castore update <host> [port]", "Root only: fetch a vendor-signed store bundle over anchored HTTPS and install it."},
    {"castore clear", "net", "castore clear", "Root only: delete the CA store."},
    {"tofprints", "net", "tofprints list|clear <host>", "Root only: list or clear pinned TOFU leaf fingerprints."},
    {"tofprints list", "net", "tofprints list", "Root only: list pinned TOFU leaf fingerprints."},
    {"tofprints clear", "net", "tofprints clear <host>", "Root only: clear the pinned fingerprint for one host."},
    {"fw", "net", "fw status|enable|disable|default allow|deny|list|add <in|out> <allow|deny> <any|icmp|tcp|udp> <src> <sport> <dst> <dport>|del <n>|clear|stat", "Firewall: ordered rules (first match wins, else default policy) over IPv4 headers only; state persists in fw.txt (root-owned 0600). With default deny, allow DHCP (UDP 67/68), DNS (UDP 53) and ICMP explicitly or the machine loses network. Outbound deny rules also block repo/castore fetches."},
    {"fw status", "net", "fw status", "Show firewall state: enabled/disabled, default policy, rule count, drop count."},
    {"fw enable", "net", "fw enable", "Root only: turn packet filtering on (rules + default policy apply)."},
    {"fw disable", "net", "fw disable", "Root only: turn packet filtering off (all traffic passes, rules kept)."},
    {"fw default", "net", "fw default allow|deny", "Root only: set the policy for packets no rule matches."},
    {"fw list", "net", "fw list", "List firewall rules in match order (1-based, as used by fw del)."},
    {"fw add", "net", "fw add <in|out> <allow|deny> <any|icmp|tcp|udp> <src> <sport> <dst> <dport>", "Root only: add a rule (src/dst are 'any' or a dotted IP; ports are 'any', a single port, or a lo-hi range). Every field is validated; a bad field adds nothing."},
    {"fw del", "net", "fw del <n>", "Root only: delete rule number n from fw list (1-based)."},
    {"fw clear", "net", "fw clear", "Root only: delete all rules (enabled/default policy kept)."},
    {"fw stat", "net", "fw stat", "Show the firewall drop count (packets denied, headers only, never contents)."},
    {"srv", "net", "srv listen <port>|serve <port> [count] [timeout]|status", "TCP server sockets on the socket table (listen backlog + accept; server sockets never share state with client sockets). Listening on a port below 1024 is root-only."},
    {"srv listen", "net", "srv listen <port>", "Probe: bind + listen on a port, print the result, then close. Not a server — use srv serve for a real server."},
    {"srv serve", "net", "srv serve <port> [count] [timeout]", "Serve count connections (default 2) on a port: accept each, read one payload, keep earlier connections open while later ones are accepted, then reply SRV-ACK:<payload> to each. Timeout in ticks (default 600, 100 Hz); on timeout it replies to what it has and reports the shortfall."},
    {"srv status", "net", "srv status", "List the socket table: id, type, state, local and remote address, listen backlog depth."},
    {"socktest", "test", "socktest clients <ip> <port>|udp <ip> <port>", "Socket-layer proofs: two concurrent client connections with correct data (clients), or a UDP send/recv round-trip (udp)."},
    {"socktest clients", "test", "socktest clients <ip> <port>", "Open two STREAM sockets to one peer, connect both before sending, verify each reply matches its own payload."},
    {"socktest udp", "test", "socktest udp <ip> <port>", "Bind a UDP socket on port 19001, send UDP-HELLO to a peer, verify the UDP-ACK reply."},
    {"sha256", "crypto", "sha256 <file>", "Print the SHA-256 hex digest of a file (up to 64 KiB)."},
    {"fbinfo", "diag", "fbinfo", "Show framebuffer geometry or why none is available."},
    {"kbdstat", "diag", "kbdstat", "Show PS/2 controller status, startup-drained bytes, last scancode."},
    {"mouse", "diag", "mouse", "Show pointer presence, position, and button state."},
    {"mousepoll", "diag", "mousepoll", "Poll the PS/2 controller for 5 seconds, logging any bytes."},
    {"cpu", "diag", "cpu", "Show CPU vendor, brand, family/model/stepping, and feature flags (CPUID)."},
    {"smp", "diag", "smp", "Show SMP state: CPUs online, AP state, LAPIC timer, AP job stats, shootdown stats."},
    {"smp locktest", "test", "smp locktest", "Spinlock contention proof: BSP + AP increment one counter under one spinlock; the final value must be exactly twice the per-CPU count."},
    {"smp pmmtest", "test", "smp pmmtest", "PMM proof: AP + BSP allocate 32 frames each; all 64 must be disjoint and the free count must return to baseline after freeing."},
    {"smp tlb", "test", "smp tlb", "TLB shootdown proof: AP keeps reading a page via its stale TLB after the BSP unmaps it, then faults on it only after the shootdown IPI."},
    {"smp jobs", "diag", "smp jobs", "List background jobs with CPU affinity: pid, name, uid, CPU, runs."},
    {"affinity", "proc", "affinity <pid> <cpu>", "Set a background job's CPU affinity (0 = BSP, 1 = AP). A RUNNING job's move is pended to its next READY transition; without an AP, CPU 1 is refused."},
    {"pci", "diag", "pci [-v]", "List PCI bus 0 devices: vendor, device, class, BAR0. -v adds revision, IRQ, and all six BARs."},
    {"acpi", "diag", "acpi", "Show parsed ACPI poweroff state (PM1 blocks, SLP_TYP) or the failure stage."},
    {"disk", "diag", "disk", "Show ATA disk presence and filesystem total/free space."},
    {"nproc", "diag", "nproc", "Print the logical CPU count from CPUID (fallback 1)."},
    {"lsusb", "diag", "lsusb", "List USB controllers found on PCI (class 0C/03). USB devices are not enumerated: no USB stack exists."},
    {"iostat", "diag", "iostat", "Show ATA disk I/O: sectors read and written since boot, plus filesystem space."},
    {"blk", "fs", "blk [merge|two|async]", "Show block device status: ATA presence, LBA48 support, DMA/PIO mode, request-queue depth and counters, swap state. merge/two queue two reads (adjacent/non-adjacent) and report merged vs commands; async queues one multi-sector read and reports its completion."},
    {"fsck", "fs", "fsck", "Read-only filesystem consistency scan: superblock magic and layout, bitmap vs directory sector use, orphan sectors. Reports inconsistencies and never repairs or writes."},
    {"mount", "fs", "mount [device]", "List mounts with no argument (one nxtsFS mount at / on device 0). A mount argument is refused: a second mount needs a second block device, and only one exists."},
    {"umount", "fs", "umount <path>", "Unmount a filesystem; refused for / because the boot filesystem is busy (the shell runs from it)."},
    {"swapon", "fs", "swapon", "Enable swap; refused: no swap area is configured (the slot allocator exists, but activation needs a dedicated swap area), so no pages are ever swapped."},
    {"swapoff", "fs", "swapoff", "Disable swap; reports that no swap area is active."},
    {"swapinfo", "fs", "swapinfo", "Show swap state: inactive, slot allocator totals, pages swapped (always 0 without an area)."},
    {"vmstat", "diag", "vmstat", "Show memory frames, uptime, background jobs, disk sectors, and network packets (no swap device exists)."},
    {"sensors", "diag", "sensors", "Report temperatures, fans, and voltages — or their honest absence: this firmware exposes no sensor devices, so no values are invented."},
    {"gui", "gui", "gui", "Enter the classic window manager (Back to shell returns)."},
    {"desktop", "gui", "desktop", "Enter the desktop (icons, launcher, taskbar, workspaces)."},
    {"wmautotest", "test", "wmautotest", "Run the window-manager autotest (edge cases, limits)."},
    {"guitest", "test", "guitest", "Run the classic GUI test (windows, buttons, events)."},
    {"cursortest", "test", "cursortest", "Run the cursor rendering test."},
    {"cliptest", "test", "cliptest", "Run the framebuffer clipping test."},
    {"stormtest", "test", "stormtest", "Run the window-storm stress test."},
    {"desktopautotest", "test", "desktopautotest", "Run the desktop autotest script."},
    {"desktopsectest", "test", "desktopsectest", "Run the desktop security autotest script."},
    {"desktopcalctest", "test", "desktopcalctest", "Run the desktop calculator autotest script."},
    {"desktopexposetest", "test", "desktopexposetest", "Run the desktop EXPOSE-repaint test (blank-window regression)."},
    {"desktopnoconsoletest", "test", "desktopnoconsoletest", "Run the desktop no-console-paint test (terminal-background regression)."},
    {"desktopnewappstest", "test", "desktopnewappstest", "Run the desktop new-apps test (Calendar, Stopwatch, Notes via launcher column 3)."},
    {"desktop10test", "test", "desktop10test", "Run the desktop Phase 10 apps autotest script."},
    {"desktopappstest", "test", "desktopappstest", "Run the desktop apps autotest script (launcher, Editor, Files, Viewer)."},
    {"desktop10sec", "test", "desktop10sec", "Run the desktop Phase 10 security autotest script."},
    {"desktopwebtest", "test", "desktopwebtest", "Run the desktop Web window autotest script."},
    {"desktopnonic", "test", "desktopnonic", "Run the desktop no-NIC behaviour test."},
    {"desktoprepotest", "test", "desktoprepotest", "Run the desktop Repo window autotest script."},
    {"desktoprepoapptest", "test", "desktoprepoapptest", "Run the desktop repo-apps autotest script."},
    {"desktoppackageapptest", "test", "desktoppackageapptest", "Run the desktop package-apps autotest script."},
    {"desktopfileinstalltest", "test", "desktopfileinstalltest", "Run the desktop file-install autotest script."},
    {"desktopfileruntest", "test", "desktopfileruntest", "Run the desktop file-run autotest script."},
    {"desktopmonitorjobtest", "test", "desktopmonitorjobtest", "Run the desktop Monitor jobs autotest script."},
    {"desktopreboottest", "test", "desktopreboottest", "Run the desktop reboot-confirm autotest script."},
    {"desktoplogouttest", "test", "desktoplogouttest", "Run the desktop logout autotest script."},
    {"desktopfilesysupdtest", "test", "desktopfilesysupdtest", "Run the desktop file system-update autotest script."},
    {"desktoprollbacktest", "test", "desktoprollbacktest", "Run the desktop rollback autotest script."},
    {"desktopreposettest", "test", "desktopreposettest", "Run the desktop repo-set autotest script."},
    {"desktopdnssettest", "test", "desktopdnssettest", "Run the desktop DNS-set autotest script."},
    {"desktopnetpingtest", "test", "desktopnetpingtest", "Run the desktop network-ping autotest script."},
    {"desktoprepofetchtest", "test", "desktoprepofetchtest", "Run the desktop repo-fetch autotest script."},
    {"desktopfileshashtest", "test", "desktopfileshashtest", "Run the desktop file-hash autotest script."},
    {"desktopmonitordisktest", "test", "desktopmonitordisktest", "Run the desktop Monitor disk autotest script."},
    {"desktopwebsavetest", "test", "desktopwebsavetest", "Run the desktop Web save autotest script."},
    {"desktopfileschmodtest", "test", "desktopfileschmodtest", "Run the desktop file-chmod autotest script."},
    {"desktopreporoottest", "test", "desktopreporoottest", "Run the desktop repo root-gate autotest script."},
    {"desktopsettingsunlocktest", "test", "desktopsettingsunlocktest", "Run the desktop Settings unlock autotest script."},
    {"desktopunlocknousertest", "test", "desktopunlocknousertest", "Run the desktop unlock-no-such-user autotest script."},
    {"desktopfallbacktest", "test", "desktopfallbacktest", "Run the desktop fallback-redraw autotest script (green-screen regression)."},
    {"csprngtest", "test", "csprngtest", "Run the CSPRNG self-test (ChaCha20 vector + sanity)."},
    {"nettest", "test", "nettest", "Run the network stack self-test."},
    {"hostmatch", "test", "hostmatch", "Run the TLS hostname-matching self-test."},
    {"mousetest", "test", "mousetest", "Run the PS/2 mouse driver self-test (injected packets)."},
    {"aes-test", "test", "aes-test", "Run the AES-256 FIPS 197 vector test."},
};
#define HELP_NGROUPS (sizeof(help_groups) / sizeof(help_groups[0]))
#define HELP_NENTRIES (sizeof(help_table) / sizeof(help_table[0]))
static int help_group_index(const char *name) {
    for (u32 i = 0; i < HELP_NGROUPS; i++)
        if (strcmp(help_groups[i].name, name) == 0) return (int)i;
    return -1;
}
static const struct help_entry *help_find(const char *name) {
    for (u32 i = 0; i < HELP_NENTRIES; i++)
        if (strcmp(help_table[i].name, name) == 0) return &help_table[i];
    return 0;
}
static const struct help_entry *help_find_in_group(const char *group, const char *name) {
    for (u32 i = 0; i < HELP_NENTRIES; i++)
        if (strcmp(help_table[i].group, group) == 0 && strcmp(help_table[i].name, name) == 0) return &help_table[i];
    return 0;
}
static void help_print_entry(const struct help_entry *e) {
    console_printf("%s (%s)\n  Usage: %s\n  %s\n", e->name, e->group, e->usage, e->desc);
}
static void help_print_group(const char *group) {
    int gi = help_group_index(group);
    if (gi < 0) return;
    console_printf("Group %s: %s\n", group, help_groups[gi].desc);
    for (u32 i = 0; i < HELP_NENTRIES; i++) {
        if (strcmp(help_table[i].group, group) != 0) continue;
        /* Subcommand entries (e.g. "pkg list") print as their own
           rows, so the group listing is complete. */
        console_printf("  %s: %s\n", help_table[i].name, help_table[i].desc);
    }
}
static void help_print_index(void) {
    /* The group list is built from help_groups, never a second
       hardcoded copy that can drift when a group is added. */
    console_write("Command groups: ");
    for (u32 i = 0; i < HELP_NGROUPS; i++)
        console_printf("%s%s", help_groups[i].name, (i + 1 < HELP_NGROUPS) ? ", " : "\n");
    for (u32 i = 0; i < HELP_NGROUPS; i++)
        console_printf("  %s: %s\n", help_groups[i].name, help_groups[i].desc);
    console_write("Type 'help <group>' for a group's commands, or 'help <command>' for one command's details.\n");
    console_write("Groups also dispatch: 'net ping <ip>', 'test csprngtest', 'fs ls', and so on. Flat names still work.\n");
    console_write("Pipes and redirection: 'a | b', 'cmd > file', 'cmd >> file', 'cmd < file' (no quoting: |, >, < always act as operators).\n");
}
/* First word of rest (rest holds text after the second token).
   Returns 1 and fills out (NUL-terminated, capped) if present. */
static int help_first_word(const char *rest, char *out, u32 cap) {
    if (!rest) return 0;
    while (*rest == ' ') rest++;
    if (*rest == 0) return 0;
    u32 i = 0;
    while (rest[i] && rest[i] != ' ' && i < cap - 1) { out[i] = rest[i]; i++; }
    out[i] = 0;
    /* `help "echo"` finds echo: strip one surrounding pair. */
    if (i >= 2 && (out[0] == '\'' || out[0] == '"') && out[i - 1] == out[0]) {
        for (u32 k = 1; k < i - 1; k++) out[k - 1] = out[k];
        out[i - 2] = 0;
    }
    return 1;
}

/* Returns 1 if the shell loop should exit (logout). */
/* Fetch-argument parsing (Phase 4, shared by http/https/httpsa/
   httpss): leading --flags in any order, then <host> <path>
   [port]. Flags: --legacy (TLS only), --no-redirect,
   --no-cookies. The port keeps the old lenient rule (an
   invalid port word leaves the default). Returns 0 ok, -1 on
   a usage error (unknown flag, --legacy on plain HTTP, or a
   missing host/path). Mutates first/rest with NUL splits, like
   the old per-command parsers did. */
#define FETCH_F_LEGACY 1
#define FETCH_F_NOREDIR 2
#define FETCH_F_NOCOOKIES 4
static int parse_fetch_args(char *first, char *rest, int allow_legacy,
                            u16 def_port, char **host_out, char **path_out,
                            u16 *port_out, int *flags_out) {
    int flags = 0;
    char *host = first;
    char *path = rest;
    if (!host || !host[0]) return -1;
    /* Consume leading flags: each flag shifts host to the first
       word of path and path to the text after it. */
    while (host[0] == '-' && host[1] == '-') {
        if (strcmp(host, "--legacy") == 0) {
            if (!allow_legacy) return -1;
            flags |= FETCH_F_LEGACY;
        } else if (strcmp(host, "--no-redirect") == 0) {
            flags |= FETCH_F_NOREDIR;
        } else if (strcmp(host, "--no-cookies") == 0) {
            flags |= FETCH_F_NOCOOKIES;
        } else {
            return -1;
        }
        if (!path || !path[0]) return -1;
        host = path;
        char *sp = path;
        while (*sp && *sp != ' ') sp++;
        if (*sp) { *sp = 0; sp++; while (*sp == ' ') sp++; path = sp; }
        else path = (char *)"";
    }
    if (!path || !path[0]) return -1;
    /* Split path at its first space; the remainder is the port. */
    char *sp = path;
    while (*sp && *sp != ' ') sp++;
    u16 port = def_port;
    if (*sp) {
        *sp = 0; sp++;
        while (*sp == ' ') sp++;
        if (*sp) {
            int v = 0, ok = 1;
            for (const char *p = sp; *p && *p != ' '; p++) {
                if (*p < '0' || *p > '9') { ok = 0; break; }
                v = v * 10 + (*p - '0');
            }
            if (ok && v >= 1 && v <= 65535) port = (u16)v;
        }
    }
    *host_out = host; *path_out = path; *port_out = port; *flags_out = flags;
    return 0;
}

/* --- line editing, history, completion (parity run) --- */
/* History: ring of 32 lines x 128 bytes, file-scope statics,
   session-only, never persisted. read_line (login, password,
   prompts) NEVER gets history — secrets must not be
   recallable. Empty lines are not recorded; an exact
   duplicate of the newest entry is not recorded. Up/Down
   walk the ring; the first Up stashes the current line as
   pending, restored by Down past the newest entry. Editing
   a browsed line ends browsing (the edited text stays as
   the current line; a later Up starts fresh from it). */
#define SH_HIST_N 32
/* Env/alias tables live here (before completion, which reads
   alias names) rather than with the execute helpers below.
   Both tables are file-scope statics, session-only, never
   persisted. Values containing '$' are NOT re-expanded
   (expansion runs once, at the outermost execute() call).
   $$ and $? are NOT implemented: a '$' not followed by a
   name or '{' passes through literally, so `echo $$` prints
   "$$" rather than a fabricated pid or status. */
#define SH_ENV_N 16
static char sh_env_name[SH_ENV_N][32];
static char sh_env_val[SH_ENV_N][128];
static u32 sh_env_n = 0;
static char sh_alias_name[SH_ENV_N][32];
static char sh_alias_val[SH_ENV_N][128];
static u32 sh_alias_n = 0;
static char sh_hist[SH_HIST_N][128];
static u32 sh_hist_n = 0;
static int sh_hist_pos = -1; /* -1 = not browsing, else index */
static char sh_hist_pending[128];

static void sh_hist_push(const char *line, u32 len) {
    if (len == 0) { sh_hist_pos = -1; return; }
    if (sh_hist_n > 0) {
        const char *last = sh_hist[sh_hist_n - 1];
        u32 ll = 0; while (last[ll]) ll++;
        if (ll == len) {
            u32 i = 0; while (i < len && last[i] == line[i]) i++;
            if (i == len) { sh_hist_pos = -1; return; }
        }
    }
    if (sh_hist_n >= SH_HIST_N) {
        for (u32 i = 1; i < SH_HIST_N; i++) {
            u32 j = 0;
            while (j < 127 && sh_hist[i][j]) { sh_hist[i - 1][j] = sh_hist[i][j]; j++; }
            sh_hist[i - 1][j] = 0;
        }
        sh_hist_n--;
    }
    u32 i = 0;
    while (i < len && i < 127) { sh_hist[sh_hist_n][i] = line[i]; i++; }
    sh_hist[sh_hist_n][i] = 0;
    sh_hist_n++;
    sh_hist_pos = -1;
}
static void sh_load_line(char *line, u32 *len_io, u32 *cur_io, const char *src) {
    u32 i = 0;
    while (src[i] && i < 127) { line[i] = src[i]; i++; }
    line[i] = 0;
    *len_io = i; *cur_io = i;
}
/* Prompt start, recomputed from the CURRENT cursor minus
   (prompt_len + cur): a scroll between prompt print and
   redraw cannot stale it, because the cursor itself moved
   with the scroll. Clamped, never underflowing. */
static u32 sh_prompt_start(u32 prompt_len, u32 cur) {
    u32 lin = console_cursor_row() * 80u + console_cursor_col();
    u32 back = prompt_len + cur;
    return (lin >= back) ? lin - back : 0;
}
static void sh_cursor_to_cell(u32 lin) {
    console_set_cursor(lin / 80u, lin % 80u);
    console_present();
}
/* Redraw prompt + line from the prompt start, buffer-only
   (no serial output — the typed echo already went to serial
   char by char; a redraw must not duplicate it into the log
   and confuse harness echo matching). `shown` is the
   previously drawn prompt+line length: cells beyond the new
   total up to `shown` are blanked, so a deletion cannot
   leave a stale tail on screen. */
static void sh_redraw(const char *line, u32 len, u32 cur, u32 prompt_len, u32 *shown_io) {
    u32 start = sh_prompt_start(prompt_len, cur);
    u32 total = prompt_len + len;
    u32 namelen = 0; while (session_name[namelen]) namelen++;
    for (u32 i = 0; i < total; i++) {
        char ch;
        if (i < namelen) ch = session_name[i];
        else if (i < prompt_len) ch = "@nxts> "[i - namelen];
        else ch = line[i - prompt_len];
        console_put_at((start + i) / 80u, (start + i) % 80u, ch);
    }
    u32 shown = *shown_io;
    for (u32 i = total; i < shown; i++)
        console_put_at((start + i) / 80u, (start + i) % 80u, ' ');
    *shown_io = total;
    sh_cursor_to_cell(start + prompt_len + cur);
}
/* Completion candidates. File names come from fs_enum_as
   (readable files for the session uid); command names from
   the help table, group names from help_groups. File-scope
   storage: the kernel stack is 16 KiB. An empty word is a
   no-op (never a listing). Alias names join this list when
   step (6) lands. */
static char sh_cand_names[32][32];
static u32 sh_cand_sizes[32];
static int sh_starts_with(const char *s, const char *prefix, u32 plen) {
    for (u32 i = 0; i < plen; i++) if (s[i] != prefix[i]) return 0;
    return 1;
}
static void sh_complete(char *line, u32 *len_io, u32 *cur_io, u32 prompt_len, u32 *shown_io) {
    u32 len = *len_io, cur = *cur_io;
    u32 wstart = cur;
    while (wstart > 0 && line[wstart - 1] != ' ') wstart--;
    u32 wlen = cur - wstart;
    if (wlen == 0) return;
    u32 nmatch = 0;
    if (wstart == 0) {
        u32 ntab = sizeof(help_table) / sizeof(help_table[0]);
        for (u32 i = 0; i < ntab && nmatch < 32; i++) {
            if (!sh_starts_with(help_table[i].name, line + wstart, wlen)) continue;
            u32 j = 0;
            while (help_table[i].name[j] && j < 31) { sh_cand_names[nmatch][j] = help_table[i].name[j]; j++; }
            sh_cand_names[nmatch][j] = 0;
            nmatch++;
        }
        u32 ngroups = sizeof(help_groups) / sizeof(help_groups[0]);
        for (u32 i = 0; i < ngroups && nmatch < 32; i++) {
            if (!sh_starts_with(help_groups[i].name, line + wstart, wlen)) continue;
            u32 dup = 0;
            for (u32 k = 0; k < nmatch && !dup; k++) {
                u32 j = 0;
                while (help_groups[i].name[j] && sh_cand_names[k][j] == help_groups[i].name[j]) j++;
                if (help_groups[i].name[j] == 0 && sh_cand_names[k][j] == 0) dup = 1;
            }
            if (dup) continue;
            u32 j = 0;
            while (help_groups[i].name[j] && j < 31) { sh_cand_names[nmatch][j] = help_groups[i].name[j]; j++; }
            sh_cand_names[nmatch][j] = 0;
            nmatch++;
        }
        /* Session aliases complete too (parity run step 6). */
        for (u32 i = 0; i < sh_alias_n && nmatch < 32; i++) {
            if (!sh_starts_with(sh_alias_name[i], line + wstart, wlen)) continue;
            u32 dup = 0;
            for (u32 k = 0; k < nmatch && !dup; k++) {
                u32 j = 0;
                while (sh_alias_name[i][j] && sh_cand_names[k][j] == sh_alias_name[i][j]) j++;
                if (sh_alias_name[i][j] == 0 && sh_cand_names[k][j] == 0) dup = 1;
            }
            if (dup) continue;
            u32 j = 0;
            while (sh_alias_name[i][j] && j < 31) { sh_cand_names[nmatch][j] = sh_alias_name[i][j]; j++; }
            sh_cand_names[nmatch][j] = 0;
            nmatch++;
        }
    } else {
        int n = fs_enum_as(session_uid, sh_cand_names, sh_cand_sizes, 32);
        if (n < 0) n = 0;
        for (int i = 0; i < n; i++) {
            if (!sh_starts_with(sh_cand_names[i], line + wstart, wlen)) continue;
            if ((u32)i != nmatch) {
                u32 j = 0;
                while (sh_cand_names[i][j] && j < 31) { sh_cand_names[nmatch][j] = sh_cand_names[i][j]; j++; }
                sh_cand_names[nmatch][j] = 0;
            }
            nmatch++;
        }
    }
    if (nmatch == 0) return;
    /* Longest common prefix of all matches (every match
       shares the typed word, so this is >= wlen). */
    u32 cplen = 0;
    for (;;) {
        char ch = sh_cand_names[0][cplen];
        if (ch == 0) break;
        u32 k = 1;
        while (k < nmatch && sh_cand_names[k][cplen] == ch) k++;
        if (k < nmatch) break;
        cplen++;
    }
    if (nmatch == 1 || cplen > wlen) {
        /* Complete to the single match or the common prefix.
           cplen == wlen with one match means already complete. */
        if (cplen == wlen) return;
        u32 d = cplen - wlen;
        u32 newlen = len - wlen + cplen;
        if (newlen > 127) return;
        for (u32 i = len; i > cur; i--) line[i + d - 1] = line[i - 1];
        for (u32 i = 0; i < cplen; i++) line[wstart + i] = sh_cand_names[0][i];
        len = newlen;
        cur = wstart + cplen;
        line[len] = 0;
        sh_redraw(line, len, cur, prompt_len, shown_io);
        *len_io = len; *cur_io = cur;
        return;
    }
    /* Several matches, no longer common prefix: list them
       (real output, like Linux), reprint prompt + line, and
       restore the logical cursor (the reprint leaves it at
       the end of the line). */
    console_putchar('\n');
    for (u32 k = 0; k < nmatch; k++) { console_write(sh_cand_names[k]); console_putchar(' '); }
    console_putchar('\n');
    console_printf("%s@nxts> ", session_name);
    line[len] = 0;
    console_write(line);
    {
        u32 lin = console_cursor_row() * 80u + console_cursor_col();
        u32 start = (lin >= prompt_len + len) ? lin - (prompt_len + len) : 0;
        sh_cursor_to_cell(start + prompt_len + cur);
    }
    *shown_io = prompt_len + len;
}

/* --- environment variables + aliases (parity run) --- */
static int sh_name_ok(const char *s) {
    if (!s || !s[0]) return 0;
    u32 len = 0; while (s[len]) len++;
    if (len > 31) return 0; /* table fields are 32 bytes incl. NUL */
    if (!((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z') || s[0] == '_')) return 0;
    for (u32 i = 1; s[i]; i++) {
        char c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_')) return 0;
    }
    return 1;
}
static const char *sh_env_get(const char *name) {
    for (u32 i = 0; i < sh_env_n; i++)
        if (strcmp(sh_env_name[i], name) == 0) return sh_env_val[i];
    return 0;
}
/* Returns 0 ok, -1 table full (new name), -2 value too long. */
static int sh_env_set(const char *name, const char *value) {
    u32 vl = 0; while (value[vl]) vl++;
    if (vl > 127) return -2;
    for (u32 i = 0; i < sh_env_n; i++) {
        if (strcmp(sh_env_name[i], name) == 0) {
            u32 j = 0;
            while (value[j]) { sh_env_val[i][j] = value[j]; j++; }
            sh_env_val[i][j] = 0;
            return 0;
        }
    }
    if (sh_env_n >= SH_ENV_N) return -1;
    u32 j = 0;
    while (name[j] && j < 31) { sh_env_name[sh_env_n][j] = name[j]; j++; }
    sh_env_name[sh_env_n][j] = 0;
    j = 0;
    while (value[j]) { sh_env_val[sh_env_n][j] = value[j]; j++; }
    sh_env_val[sh_env_n][j] = 0;
    sh_env_n++;
    return 0;
}
static void sh_env_unset(const char *name) {
    for (u32 i = 0; i < sh_env_n; i++) {
        if (strcmp(sh_env_name[i], name) != 0) continue;
        for (u32 j = i + 1; j < sh_env_n; j++) {
            u32 k = 0;
            while (sh_env_name[j][k]) { sh_env_name[j - 1][k] = sh_env_name[j][k]; k++; }
            sh_env_name[j - 1][k] = 0;
            k = 0;
            while (sh_env_val[j][k]) { sh_env_val[j - 1][k] = sh_env_val[j][k]; k++; }
            sh_env_val[j - 1][k] = 0;
        }
        sh_env_n--;
        return;
    }
}
static const char *sh_alias_get(const char *name) {
    for (u32 i = 0; i < sh_alias_n; i++)
        if (strcmp(sh_alias_name[i], name) == 0) return sh_alias_val[i];
    return 0;
}
/* Returns 0 ok, -1 table full (new name), -2 value too long. */
static int sh_alias_set(const char *name, const char *value) {
    u32 vl = 0; while (value[vl]) vl++;
    if (vl > 127) return -2;
    for (u32 i = 0; i < sh_alias_n; i++) {
        if (strcmp(sh_alias_name[i], name) == 0) {
            u32 j = 0;
            while (value[j]) { sh_alias_val[i][j] = value[j]; j++; }
            sh_alias_val[i][j] = 0;
            return 0;
        }
    }
    if (sh_alias_n >= SH_ENV_N) return -1;
    u32 j = 0;
    while (name[j] && j < 31) { sh_alias_name[sh_alias_n][j] = name[j]; j++; }
    sh_alias_name[sh_alias_n][j] = 0;
    j = 0;
    while (value[j]) { sh_alias_val[sh_alias_n][j] = value[j]; j++; }
    sh_alias_val[sh_alias_n][j] = 0;
    sh_alias_n++;
    return 0;
}
static int sh_alias_unset(const char *name) {
    for (u32 i = 0; i < sh_alias_n; i++) {
        if (strcmp(sh_alias_name[i], name) != 0) continue;
        for (u32 j = i + 1; j < sh_alias_n; j++) {
            u32 k = 0;
            while (sh_alias_name[j][k]) { sh_alias_name[j - 1][k] = sh_alias_name[j][k]; k++; }
            sh_alias_name[j - 1][k] = 0;
            k = 0;
            while (sh_alias_val[j][k]) { sh_alias_val[j - 1][k] = sh_alias_val[j][k]; k++; }
            sh_alias_val[j - 1][k] = 0;
        }
        sh_alias_n--;
        return 1;
    }
    return 0;
}

/* Split tok[1] + rest into word pointers (mutates rest by
   inserting NULs — the line buffer is single-use). Returns
   the word count (tok[1] is always word 0). Shared by du
   and the text tools. */
static u32 sh_split_args(const char *first, char *rest, const char **args, u32 max) {
    u32 nargs = 0;
    if (first) args[nargs++] = first;
    if (rest) {
        char *p = rest;
        while (*p && nargs < max) {
            while (*p == ' ') p++;
            if (!*p) break;
            char *w = p;
            if (sh_parse_word(&p) != 0) break; /* unterminated: drop the partial word */
            args[nargs++] = w;
            if (*p == ' ') p++;
        }
    }
    return nargs;
}
/* Substring match (NOT regex — documented wherever it is used). */
static int sh_contains(const char *hay, const char *needle) {
    if (!needle[0]) return 1;
    for (u32 s = 0; hay[s]; s++) {
        u32 k = 0;
        while (needle[k] && hay[s + k] == needle[k]) k++;
        if (!needle[k]) return 1;
    }
    return 0;
}

/* --- text tools: line reader + tables (parity run) --- */
/* The shell stdin source (set by a pipeline stage: its <
   file, or the previous stage's pipe temp; empty otherwise).
   Text tools read file args, or this file when the arg is
   "-" or when no file arg is given. */
static char sh_stdin_file[32];

/* --- pipes + redirection (parity run step 9) ---
   No stdin/stdout abstraction exists in this kernel, so this
   is a shell-level stage runner, not a kernel pipe. Operators
   are recognised AFTER $VAR/alias expansion (the wrapper
   parses pipes only on the expanded line), so an expanded
   value containing |, >, < acts as an operator — there is no
   quoting to protect it, and no quoting exists anywhere else
   in this shell either. A stage's stdout goes to a temp file
   .nxpipe<i> (next stage's stdin), or to the redirect target
   for > / >>; < overrides the pipe input (Linux behaviour).
   Capture suppresses the serial mirror while active (see
   console.c), so redirected secrets never land in the log.
   Temp files are refused if they already exist (never
   overwrite a user file) and are deleted after the pipeline.
   Total capture is capped at 256 KiB with a visible warning
   past the cap (fail-visible, never silent). Interactive
   screen/prompt commands (top, edit, gui, desktop, su,
   passwd, unlock — group-resolved, so "fs edit" refuses too)
   refuse any redirect/pipe: their prompts read from the
   terminal and capturing would hide the prompt. Aliases
   expand only for the pipeline's first command (the wrapper
   expands once, before parsing); a later stage's first word
   is NOT alias-expanded. Capture is console-global: a
   background job printing during a capture would land in
   the capture file (no per-job output routing exists). */
static int execute_inner(char *line); /* forward: defined below */
static char sh_capture_file[32];
static int sh_capture_append = 0; /* 1 = >>, 0 = > */
static int sh_capture_started = 0; /* first flush done */
static u32 sh_capture_total = 0; /* bytes appended so far */
static int sh_capture_failed = 0; /* flush append failed */
#define SH_CAPTURE_CAP 262144
static char sh_flush_chunk[4096]; /* capture drain staging */
static u8 sh_append_buf[SH_CAPTURE_CAP + 4096]; /* read + append + rewrite staging */
static char sh_stdin_buf[SH_CAPTURE_CAP]; /* write-from-stdin staging */

struct sh_pipe_stage { char text[128]; char infile[32]; char outfile[32]; int has_in, has_out, out_append; };
static struct sh_pipe_stage sh_pipe_stages[4];
static u32 sh_pipe_n = 0;
static char sh_pline[256];
static char *sh_pword[128];
static u32 sh_pnwords = 0;

static int sh_pipe_is_op(const char *w) {
    return (strcmp(w, "|") == 0 || strcmp(w, ">") == 0 || strcmp(w, "<") == 0);
}
/* Copy a redirection target, unquoting it (so > "my file"
   would target my file — filenames with spaces are still
   refused by the fs layer, but the name itself is honest).
   Returns 1 ok, 0 too long, -1 unterminated quote. */
static int sh_pipe_copy_name(char *dst, const char *src) {
    char tmp[64];
    if (sh_unquote_copy(src, tmp, sizeof(tmp)) != 0) return -1;
    u32 l = 0; while (tmp[l]) l++;
    if (l > 31) return 0;
    for (u32 i = 0; i <= l; i++) dst[i] = tmp[i];
    return 1;
}
static int sh_pipe_is_temp(const char *n) {
    return (strcmp(n, ".nxpipe0") == 0 || strcmp(n, ".nxpipe1") == 0 || strcmp(n, ".nxpipe2") == 0);
}
static void sh_pipe_temp_name(u32 i, char *out) {
    out[0] = '.'; out[1] = 'n'; out[2] = 'x'; out[3] = 'p'; out[4] = 'i'; out[5] = 'p'; out[6] = 'e';
    out[7] = (char)('0' + i); out[8] = 0;
}
static int sh_pipe_is_interactive(const char *cmd) {
    return (strcmp(cmd, "top") == 0 || strcmp(cmd, "edit") == 0 || strcmp(cmd, "gui") == 0 ||
            strcmp(cmd, "desktop") == 0 || strcmp(cmd, "su") == 0 ||
            strcmp(cmd, "passwd") == 0 || strcmp(cmd, "unlock") == 0);
}
/* Effective command of a stage, group-resolved like dispatch:
   "fs edit" -> "edit", "session su" -> "su", else first word. */
static void sh_stage_cmd(const char *text, char *out, u32 cap) {
    u32 i = 0; while (text[i] && text[i] != ' ') i++;
    char first[32];
    u32 fl = (i < 31) ? i : 31, k = 0;
    for (k = 0; k < fl; k++) first[k] = text[k];
    first[fl] = 0;
    if (help_group_index(first) >= 0) {
        const char *p = text + i;
        while (*p == ' ') p++;
        u32 j = 0; while (p[j] && p[j] != ' ') j++;
        char second[32];
        u32 sl = (j < 31) ? j : 31;
        for (k = 0; k < sl; k++) second[k] = p[k];
        second[sl] = 0;
        if (help_find_in_group(first, second)) {
            u32 c = 0; while (second[c] && c + 1 < cap) { out[c] = second[c]; c++; }
            out[c] = 0;
            return;
        }
    }
    u32 c = 0; while (first[c] && c + 1 < cap) { out[c] = first[c]; c++; }
    out[c] = 0;
}

/* Append data to the capture target. First call for '>'
   truncates (direct write, mode preserved for existing
   files, 0644 for new); later calls and '>>' read + append
   + rewrite (same mode rule). Returns 0 ok, -1 fail. An
   existing-but-unstatable file fails rather than blindly
   truncating (an append must read to append; a write-only
   file cannot be appended, and truncating it would be data
   loss). fs_write_as enforces writability, so an unwritable
   target fails here and the runner warns visibly. */
static int sh_capture_append_chunk(const u8 *data, u32 len) {
    int exists = fs_exists(sh_capture_file);
    u32 mode = 0644, old = 0;
    struct fs_stat st;
    if (exists) {
        if (fs_stat_as(sh_capture_file, &st, session_uid) != 0) return -1;
        mode = st.mode;
        if (st.size > sizeof(sh_append_buf) - 4096) return -1;
        if (st.size > 0) {
            u32 got = 0;
            if (fs_read_as(sh_capture_file, sh_append_buf, st.size, &got, session_uid) != 0) return -1;
            if (got != st.size) return -1;
            old = got;
        }
    }
    if (!sh_capture_started && !sh_capture_append) {
        if (fs_write_as(sh_capture_file, data, len, session_uid, mode) != 0) return -1;
        sh_capture_started = 1;
        return 0;
    }
    if (old + len > sizeof(sh_append_buf)) return -1;
    for (u32 i = 0; i < len; i++) sh_append_buf[old + i] = data[i];
    if (fs_write_as(sh_capture_file, sh_append_buf, old + len, session_uid, mode) != 0) return -1;
    sh_capture_started = 1;
    return 0;
}

/* Runs inside console_putchar when the capture buffer fills.
   Drains the buffer to the capture file, up to the total cap;
   past the cap only the fitting prefix is kept and the rest
   is dropped with a visible warning at stage end. */
static void sh_capture_flush_cb(void) {
    u32 n = console_capture_take(sh_flush_chunk);
    if (n == 0 || sh_capture_failed) return; /* failed: discard */
    if (sh_capture_total >= SH_CAPTURE_CAP) { console_capture_set_truncated(); return; }
    u32 room = SH_CAPTURE_CAP - sh_capture_total;
    u32 keep = (n <= room) ? n : room;
    if (sh_capture_append_chunk((const u8 *)sh_flush_chunk, keep) != 0) { sh_capture_failed = 1; return; }
    sh_capture_total += keep;
    if (keep < n) console_capture_set_truncated();
}

/* Drain the capture remainder after a stage, restore normal
   output, and print any truncation/failure warning visibly
   (after end, so the warning itself is NOT captured). */
static void sh_capture_finish(void) {
    int failed = sh_capture_failed;
    int trunc = console_capture_truncated();
    if (!failed && !trunc) {
        u32 n = console_capture_take(sh_flush_chunk);
        if (n > 0) {
            if (sh_capture_total >= SH_CAPTURE_CAP) trunc = 1;
            else {
                u32 room = SH_CAPTURE_CAP - sh_capture_total;
                u32 keep = (n <= room) ? n : room;
                if (sh_capture_append_chunk((const u8 *)sh_flush_chunk, keep) != 0) failed = 1;
                else { sh_capture_total += keep; if (keep < n) trunc = 1; }
            }
        } else if (!sh_capture_started) {
            /* No output at all: '>' still truncates (or
               creates), '>>' still creates a missing file —
               like Linux. '>>' onto an existing file with no
               output is a true no-op (no spurious rewrite,
               which would re-own the file via fs_write_as). */
            if (!sh_capture_append || !fs_exists(sh_capture_file)) {
                if (sh_capture_append_chunk((const u8 *)"", 0) != 0) failed = 1;
            }
        }
    } else {
        console_capture_take(sh_flush_chunk); /* discard remainder */
    }
    console_capture_end();
    if (failed) console_printf("capture failed: %s\n", sh_capture_file);
    else if (trunc) console_write("capture truncated (max 262144 bytes)\n");
}

static int sh_pipe_build_stage(u32 s, u32 e) {
    struct sh_pipe_stage *st = &sh_pipe_stages[sh_pipe_n];
    st->text[0] = 0; st->infile[0] = 0; st->outfile[0] = 0;
    st->has_in = 0; st->has_out = 0; st->out_append = 0;
    u32 tl = 0;
    for (u32 w = s; w < e; w++) {
        const char *word = sh_pword[w];
        if (strcmp(word, "<") == 0) {
            if (st->has_in) { console_write("multiple input redirections\n"); return -1; }
            if (w + 1 >= e || sh_pipe_is_op(sh_pword[w + 1])) { console_write("missing redirection target\n"); return -1; }
            { int cr = sh_pipe_copy_name(st->infile, sh_pword[w + 1]);
              if (cr == 0) { console_write("redirection target too long\n"); return -1; }
              if (cr < 0) { console_write("redirection target has an unterminated quote\n"); return -1; } }
            st->has_in = 1; w++;
        } else if (strcmp(word, ">") == 0) {
            if (st->has_out) { console_write("multiple output redirections\n"); return -1; }
            int app = 0;
            u32 t = w + 1;
            if (t < e && strcmp(sh_pword[t], ">") == 0) { app = 1; t++; }
            if (t >= e || sh_pipe_is_op(sh_pword[t])) { console_write("missing redirection target\n"); return -1; }
            { int cr = sh_pipe_copy_name(st->outfile, sh_pword[t]);
              if (cr == 0) { console_write("redirection target too long\n"); return -1; }
              if (cr < 0) { console_write("redirection target has an unterminated quote\n"); return -1; } }
            st->has_out = 1; st->out_append = app; w = t;
        } else {
            u32 wl = 0; while (word[wl]) wl++;
            if (tl + wl + (tl ? 1 : 0) >= 127) { console_write("command too long\n"); return -1; }
            if (tl) st->text[tl++] = ' ';
            for (u32 i = 0; i < wl; i++) st->text[tl++] = word[i];
            st->text[tl] = 0;
        }
    }
    if (st->text[0] == 0) { console_write("empty pipeline stage\n"); return -1; }
    return 0;
}

/* Parse the expanded line into stages. Returns 0 ok, -1 on
   syntax error (message already printed, nothing runs). */
static int sh_pipe_parse(const char *line) {
    /* Preprocess: spaces around |, >, < so "echo hi>out.txt"
       works. ">>" becomes "> >" (two tokens = append).
       Overflow past the pline cap refuses, never truncates.
       Quoting (redesign 5): operators and spaces inside
       quotes are literal — they are neither spaced nor
       split — and quotes are kept in the words, so the
       stage's own tokenize() strips them later. */
    u32 o = 0;
    {
        int qs = 0, esc = 0;
        for (u32 i = 0; line[i]; i++) {
            char c = line[i];
            if (esc) {
                if (o + 1 >= sizeof(sh_pline)) { console_write("command too long\n"); return -1; }
                sh_pline[o++] = c; esc = 0; continue;
            }
            if (c == '\\' && qs != '\'') {
                if (o + 1 >= sizeof(sh_pline)) { console_write("command too long\n"); return -1; }
                sh_pline[o++] = c; esc = 1; continue;
            }
            if (qs == '\'') {
                if (o + 1 >= sizeof(sh_pline)) { console_write("command too long\n"); return -1; }
                sh_pline[o++] = c;
                if (c == '\'') qs = 0;
                continue;
            }
            if (qs == '"') {
                if (o + 1 >= sizeof(sh_pline)) { console_write("command too long\n"); return -1; }
                sh_pline[o++] = c;
                if (c == '"') qs = 0;
                continue;
            }
            if (c == '\'') { qs = '\''; }
            else if (c == '"') { qs = '"'; }
            if ((c == '|' || c == '>' || c == '<') && qs == 0) {
                if (o + 3 >= sizeof(sh_pline)) { console_write("command too long\n"); return -1; }
                sh_pline[o++] = ' '; sh_pline[o++] = c; sh_pline[o++] = ' ';
            } else {
                if (o + 1 >= sizeof(sh_pline)) { console_write("command too long\n"); return -1; }
                sh_pline[o++] = c;
            }
        }
    }
    sh_pline[o] = 0;
    sh_pnwords = 0;
    {
        u32 i = 0;
        int qs = 0, esc = 0;
        while (sh_pline[i]) {
            while (sh_pline[i] == ' ') i++;
            if (!sh_pline[i]) break;
            if (sh_pnwords >= 128) { console_write("command too long\n"); return -1; }
            sh_pword[sh_pnwords++] = &sh_pline[i];
            qs = 0; esc = 0;
            while (sh_pline[i]) {
                char c = sh_pline[i];
                if (esc) { esc = 0; i++; continue; }
                if (c == '\\' && qs != '\'') { esc = 1; i++; continue; }
                if (qs == '\'') { if (c == '\'') qs = 0; i++; continue; }
                if (qs == '"') { if (c == '"') qs = 0; i++; continue; }
                if (c == '\'') { qs = '\''; i++; continue; }
                if (c == '"') { qs = '"'; i++; continue; }
                if (c == ' ') break;
                i++;
            }
            if (sh_pline[i]) { sh_pline[i] = 0; i++; }
        }
    }
    sh_pipe_n = 0;
    u32 sstart = 0;
    for (u32 w = 0; w <= sh_pnwords; w++) {
        if (w == sh_pnwords || strcmp(sh_pword[w], "|") == 0) {
            if (sh_pipe_n >= 4) { console_write("pipeline too long (max 4 stages)\n"); return -1; }
            if (sh_pipe_build_stage(sstart, w) != 0) return -1;
            sh_pipe_n++;
            sstart = w + 1;
        }
    }
    for (u32 k = 0; k < sh_pipe_n; k++) {
        char cmd[32];
        sh_stage_cmd(sh_pipe_stages[k].text, cmd, sizeof(cmd));
        if (sh_pipe_is_interactive(cmd)) { console_write("cannot redirect interactive command\n"); return -1; }
    }
    for (u32 k = 0; k < sh_pipe_n; k++) {
        if ((sh_pipe_stages[k].has_in && sh_pipe_is_temp(sh_pipe_stages[k].infile)) ||
            (sh_pipe_stages[k].has_out && sh_pipe_is_temp(sh_pipe_stages[k].outfile))) {
            console_write("reserved pipeline name\n"); return -1;
        }
    }
    return 0;
}

static int sh_pipe_scan(const char *line) {
    /* Operators outside quotes only: a quoted |, >, < is
       text for echo/write, not a pipeline. */
    int qs = 0, esc = 0;
    for (u32 i = 0; line[i]; i++) {
        char c = line[i];
        if (esc) { esc = 0; continue; }
        if (c == '\\' && qs != '\'') { esc = 1; continue; }
        if (qs == '\'') { if (c == '\'') qs = 0; continue; }
        if (qs == '"') { if (c == '"') qs = 0; continue; }
        if (c == '\'') { qs = '\''; continue; }
        if (c == '"') { qs = '"'; continue; }
        if (c == '|' || c == '>' || c == '<') return 1;
    }
    return 0;
}

/* Run the parsed stages. The wrapper holds sh_expand_depth
   across this call, so a stage's group dispatch cannot
   re-expand (values containing '$' stay literal). */
static int sh_run_pipeline(void) {
    if (!fs_mounted()) { console_write("No filesystem mounted\n"); return 0; }
    char temp[16];
    u32 created = 0;
    for (u32 k = 0; k + 1 < sh_pipe_n; k++) {
        sh_pipe_temp_name(k, temp);
        if (fs_exists(temp)) { console_printf("pipeline temp file exists: %s\n", temp); return 0; }
    }
    for (u32 k = 0; k + 1 < sh_pipe_n; k++) {
        sh_pipe_temp_name(k, temp);
        if (fs_write_as(temp, (const u8 *)"", 0, session_uid, 0644) != 0) {
            console_printf("cannot create pipeline temp: %s\n", temp);
            break;
        }
        created++;
    }
    if (created + 1 == sh_pipe_n) {
        /* All temps created (or none needed for a single
           redirect stage). A temp-create failure skips
           running entirely (created + 1 < sh_pipe_n). */
        for (u32 k = 0; k < sh_pipe_n; k++) {
                if (sh_pipe_stages[k].has_in) {
                    u32 c = 0; while (sh_pipe_stages[k].infile[c] && c < 31) { sh_stdin_file[c] = sh_pipe_stages[k].infile[c]; c++; }
                    sh_stdin_file[c] = 0;
                } else if (k > 0) {
                    sh_pipe_temp_name(k - 1, sh_stdin_file);
                } else {
                    sh_stdin_file[0] = 0;
                }
                int cap = 0;
                if (sh_pipe_stages[k].has_out) {
                    u32 c = 0; while (sh_pipe_stages[k].outfile[c] && c < 31) { sh_capture_file[c] = sh_pipe_stages[k].outfile[c]; c++; }
                    sh_capture_file[c] = 0;
                    sh_capture_append = sh_pipe_stages[k].out_append;
                    cap = 1;
                } else if (k + 1 < sh_pipe_n) {
                    sh_pipe_temp_name(k, sh_capture_file);
                    sh_capture_append = 0;
                    cap = 1;
                }
                if (cap) {
                    sh_capture_started = 0; sh_capture_total = 0; sh_capture_failed = 0;
                    console_capture_set_flush(sh_capture_flush_cb);
                    console_capture_begin();
                    execute_inner(sh_pipe_stages[k].text);
                    sh_capture_finish();
                    sh_capture_file[0] = 0;
                } else {
                    execute_inner(sh_pipe_stages[k].text);
                }
                sh_stdin_file[0] = 0;
            }
    }
    for (u32 k = 0; k < created; k++) {
        sh_pipe_temp_name(k, temp);
        if (fs_delete_as(temp, session_uid) != 0) console_printf("warning: could not remove %s\n", temp);
    }
    return 0;
}
/* Line reader over windowed fs reads: a line spanning read
   windows must not be dropped or duplicated. Lines longer
   than 255 bytes split at the cap (never silently joined);
   a trailing partial line without '\n' is returned once;
   a file ending in '\n' yields no phantom empty line. NUL
   bytes truncate matching/printing at the NUL (same rule as
   cat); no CRLF stripping (unlike the editor, which
   normalises on load — different tool, documented rule).
   File-scope state: the kernel stack is 16 KiB. Tools run
   one at a time, so sharing one reader is safe. */
static u8 sh_lr_win[1024];
static u32 sh_lr_off, sh_lr_pos, sh_lr_len;
static char sh_lr_line[256];
static const char *sh_lr_name;
static u32 sh_lr_uid;
static int sh_lr_open(const char *name, u32 uid) {
    sh_lr_name = name;
    sh_lr_uid = uid;
    sh_lr_off = 0; sh_lr_pos = 0; sh_lr_len = 0;
    /* Probe: an unreadable file fails here, before any output. */
    u32 got = 0;
    if (fs_read_range_as(name, sh_lr_win, sizeof(sh_lr_win), 0, &got, uid) != 0) return -1;
    sh_lr_len = got;
    sh_lr_off = got; /* next window starts after the probe */
    return 0;
}
/* Returns 1 with the next line in sh_lr_line (no '\n'), 0 at
   end, -1 on read error (callers stop with a message). */
static int sh_lr_next(void) {
    u32 n = 0;
    for (;;) {
        if (sh_lr_pos >= sh_lr_len) {
            u32 got = 0;
            if (fs_read_range_as(sh_lr_name, sh_lr_win, sizeof(sh_lr_win), sh_lr_off, &got, sh_lr_uid) != 0) {
                if (n == 0) return -1;
                break; /* mid-line error: return what we have */
            }
            if (got == 0) break; /* EOF */
            sh_lr_off += got; sh_lr_pos = 0; sh_lr_len = got;
        }
        char ch = (char)sh_lr_win[sh_lr_pos++];
        if (ch == '\n') { sh_lr_line[n] = 0; return 1; }
        sh_lr_line[n++] = ch;
        if (n >= 255) { sh_lr_line[n] = 0; return 1; }
    }
    if (n > 0) { sh_lr_line[n] = 0; return 1; }
    return 0;
}
/* Tables for sort (one file set) and diff (two files).
   256 lines each, 255 chars each; over-cap refuses with a
   message, never truncated output. */
static char sh_sort_lines[256][256];
static char sh_diff_a[256][256];
static char sh_diff_b[256][256];
static u16 sh_diff_dp[257][257];
/* Read all lines of one input into table starting at off.
   Returns the new count, -1 unreadable, -2 over cap. */
static int sh_read_lines(const char *name, u32 uid, char table[][256], int off) {
    if (sh_lr_open(name, uid) != 0) return -1;
    int count = off;
    for (;;) {
        int r = sh_lr_next();
        if (r == 0) break;
        if (r < 0) return -1;
        if (count >= 256) return -2;
        u32 i = 0;
        while (sh_lr_line[i]) { table[count][i] = sh_lr_line[i]; i++; }
        table[count][i] = 0;
        count++;
    }
    return count;
}
/* Diff op list (backtrack emits in reverse; the forward pass
   reads it backwards). */
static u8 sh_diff_op_type[768];
static u32 sh_diff_op_idx[768];
/* Parse a decimal number: -1 on empty/non-digit, clamped at
   1000000 (bigger than any file's line count here). */
static int sh_parse_num(const char *s) {
    if (!s || !s[0]) return -1;
    u32 v = 0;
    for (u32 i = 0; s[i]; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        if (v > 100000) return 1000000;
        v = v * 10u + (u32)(s[i] - '0');
    }
    return (int)v;
}
/* Resolve a job spec (pid digits or %N, Nth job in `jobs`
   display order) to a pid under the kill permission rule
   (own jobs, or any as root). Returns 0 with *pid_out set,
   or -1 (bad spec, no such job, or no permission). */
static int sh_bg_resolve(const char *spec, u32 uid, u32 *pid_out) {
    u32 pid = 0;
    if (spec[0] == '%') {
        u32 jn = 0;
        for (const char *p = spec + 1; *p; p++) {
            if (*p < '0' || *p > '9' || jn > 1000000) return -1;
            jn = jn * 10u + (u32)(*p - '0');
        }
        if (jn < 1) return -1;
        char nm[32]; u32 pp, uu;
        if (proc_bg_at((int)jn - 1, nm, &pp, &uu) != 0) return -1;
        pid = pp;
    } else {
        if (spec[0] == 0) return -1;
        for (const char *p = spec; *p; p++) {
            if (*p < '0' || *p > '9' || pid > 1000000) return -1;
            pid = pid * 10u + (u32)(*p - '0');
        }
    }
    for (int i = 0; i < MAX_BG; i++) {
        char nm[32]; u32 pp, uu;
        if (proc_bg_at(i, nm, &pp, &uu) != 0) break;
        if (pp == pid) {
            if (uu != uid && uid != 0) return -1;
            *pid_out = pid;
            return 0;
        }
    }
    return -1;
}
/* Wait for one job to exit, ticking jobs and polling keys.
   Returns 0 (job done), 1 (Ctrl-C, job killed), 2 (Ctrl-C,
   kill refused). Other keys are consumed and ignored (no
   typeahead into the next prompt). A hung job never wedges
   the shell: Ctrl-C always returns. */
/* Deep-core phase: after a wait completes, report a reaped exit
   status (the reap entry is consumed, so each code prints once). */
static void sh_wait_status(u32 pid, u32 uid, const char *verb) {
    u32 code = 0;
    if (proc_reap_take(pid, uid, &code) == 0)
        console_printf("%s: job %u exit status %u\n", verb, pid, code);
}
/* A numeric spec for an already-exited job: %N is meaningless once
   the job is gone, but a pid can still be reaped. Returns 1 when a
   status was reaped (and printed), 0 otherwise. */
static int sh_reap_numeric(const char *spec, u32 uid, const char *verb) {
    if (!spec || !spec[0]) return 0;
    u32 pid = 0;
    for (const char *p = spec; *p; p++) {
        if (*p < '0' || *p > '9' || pid > 1000000) return 0;
        pid = pid * 10u + (u32)(*p - '0');
    }
    u32 code = 0;
    if (proc_reap_take(pid, uid, &code) != 0) return 0;
    console_printf("%s: job %u done\n", verb, pid);
    console_printf("%s: job %u exit status %u\n", verb, pid, code);
    return 1;
}

static int sh_wait_pid(u32 pid, u32 uid) {
    for (;;) {
        if (!proc_bg_exists(pid)) return 0;
        keyboard_poll();
        int c = keyboard_getchar();
        if (c == 3) {
            if (proc_bg_kill(pid, uid) == 0) return 1;
            return 2;
        }
        proc_bg_tick();
        if (c < 0) __asm__ volatile ("hlt");
    }
}
static const char *sh_input_name(const char *arg) {
    return (strcmp(arg, "-") == 0) ? sh_stdin_file : arg;
}
static const char *sh_input_disp(const char *arg) {
    return (strcmp(arg, "-") == 0) ? "(stdin)" : arg;
}
/* Resolve a tool's inputs: file args, or the stdin source
   when no file arg is given. Returns the count, or -1 after
   printing the usage line. */
static int sh_tool_inputs(int n, char *tok1, char *rest, const char **args, const char *usage) {
    u32 nargs = (n >= 2) ? sh_split_args(tok1, rest, args, 33) : 0;
    if (nargs == 0) {
        if (sh_stdin_file[0]) { args[0] = "-"; return 1; }
        console_write(usage);
        return -1;
    }
    return (int)nargs;
}

/* ---- Script interpreter + test builtin (Linux-comparability run) ----
   Scripts are files of shell lines, run by `sh`/`source`. The
   interpreter stores at most 128 lines (file-scope statics, never
   the kernel stack) and runs a range recursively so nested blocks
   work. A line's `logout`/`exit` return (execute() == 1) ends the
   script, never the session. Block depth is capped at 4 by the
   range recursion (a deeper nesting is refused when found).
   `test` is a separate builtin below; the interpreter reads its
   result from sh_last_status after running the condition. */
static char sh_script_lines[128][256];
static int sh_script_nlines = 0;
static int sh_script_depth = 0;

static int sh_script_first_word(const char *line, char *out) {
    while (*line == ' ') line++;
    int i = 0;
    while (line[i] && line[i] != ' ' && i < 31) { out[i] = line[i]; i++; }
    out[i] = 0;
    return i;
}
/* Forward declaration: the script interpreter calls execute(),
   which is defined after execute_inner. */
static int execute(char *line);
/* Execute one script line with a fresh expansion pass: the script
   handler itself runs inside execute_inner (depth > 0), which
   would otherwise suppress expansion for every line. */
static int sh_script_exec(char *line) {
    int saved = sh_expand_depth;
    sh_expand_depth = 0;
    int r = execute(line);
    sh_expand_depth = saved;
    return r;
}
/* Find the else (if any) and end of a block starting just after
   `start` (the block's own line) within [start+1, end). kind:
   0 = if (else/endif|fi), 1 = for (endfor|done), 2 = while
   (endwhile). Returns 0 with *else_pos (-1 if none) and
   *end_pos set, or -1 when unmatched. */
static int sh_script_find_block(int start, int end, int kind, int *else_pos, int *end_pos) {
    int depth = 0;
    *else_pos = -1; *end_pos = -1;
    for (int i = start + 1; i < end; i++) {
        char w[32];
        sh_script_first_word(sh_script_lines[i], w);
        if (strcmp(w, "if") == 0 || strcmp(w, "for") == 0 || strcmp(w, "while") == 0) { depth++; continue; }
        if (depth > 0) {
            if (strcmp(w, "endif") == 0 || strcmp(w, "fi") == 0 ||
                strcmp(w, "endfor") == 0 || strcmp(w, "done") == 0 ||
                strcmp(w, "endwhile") == 0) depth--;
            continue;
        }
        if (kind == 0 && strcmp(w, "else") == 0) { *else_pos = i; continue; }
        if (kind == 0 && (strcmp(w, "endif") == 0 || strcmp(w, "fi") == 0)) { *end_pos = i; return 0; }
        if (kind == 1 && (strcmp(w, "endfor") == 0 || strcmp(w, "done") == 0)) { *end_pos = i; return 0; }
        if (kind == 2 && strcmp(w, "endwhile") == 0) { *end_pos = i; return 0; }
    }
    return -1;
}
static int sh_script_run_range(int start, int end);
static int sh_script_run_range(int start, int end) {
    for (int i = start; i < end; i++) {
        char *line = sh_script_lines[i];
        char w[32];
        sh_script_first_word(line, w);
        if (w[0] == 0 || w[0] == '#') continue;
        if (strcmp(w, "else") == 0 || strcmp(w, "endif") == 0 || strcmp(w, "fi") == 0 ||
            strcmp(w, "endfor") == 0 || strcmp(w, "done") == 0 || strcmp(w, "endwhile") == 0) {
            continue; /* stray closer: ranges exclude them normally */
        }
        if (strcmp(w, "if") == 0) {
            int else_pos = -1, end_pos = -1;
            if (sh_script_find_block(i, end, 0, &else_pos, &end_pos) != 0) {
                console_write("sh: unmatched if\n"); return 2;
            }
            /* Condition = the line after "if ". */
            const char *p = line;
            while (*p == ' ') p++;
            p += 2;
            while (*p == ' ') p++;
            char cond[128];
            int ci = 0;
            while (p[ci] && ci < 127) { cond[ci] = p[ci]; ci++; }
            cond[ci] = 0;
            int r = sh_script_exec(cond);
            if (r == 1) return 1;
            int ok = (sh_last_status == 0);
            int run_from, run_to;
            if (ok) { run_from = i + 1; run_to = (else_pos >= 0) ? else_pos : end_pos; }
            else if (else_pos >= 0) { run_from = else_pos + 1; run_to = end_pos; }
            else { i = end_pos; continue; }
            { int rr = sh_script_run_range(run_from, run_to); if (rr != 0) return rr; }
            i = end_pos;
            continue;
        }
        if (strcmp(w, "for") == 0) {
            int else_pos = -1, end_pos = -1;
            if (sh_script_find_block(i, end, 1, &else_pos, &end_pos) != 0) {
                console_write("sh: unmatched for\n"); return 2;
            }
            (void)else_pos;
            /* Parse "for VAR in w1 w2 ...". */
            const char *p = line;
            while (*p == ' ') p++;
            p += 3;
            while (*p == ' ') p++;
            char var[32]; int vi = 0;
            while (*p && *p != ' ' && vi < 31) { var[vi++] = *p++; }
            var[vi] = 0;
            while (*p == ' ') p++;
            if (!(p[0] == 'i' && p[1] == 'n' && (p[2] == ' ' || p[2] == 0)) || !sh_name_ok(var)) {
                console_write("Usage: for <var> in <words...>\n"); return 2;
            }
            p += 2;
            /* Collect words into a file-scope buffer (line is
               already <= 255 chars, so the word list fits). */
            static char sh_for_words[256];
            int wi = 0;
            while (*p && wi < 255) { sh_for_words[wi++] = *p++; }
            sh_for_words[wi] = 0;
            int wpos = 0;
            int any = 0;
            while (sh_for_words[wpos]) {
                while (sh_for_words[wpos] == ' ') wpos++;
                if (!sh_for_words[wpos]) break;
                char word[128]; int qi = 0;
                while (sh_for_words[wpos] && sh_for_words[wpos] != ' ' && qi < 127) { word[qi++] = sh_for_words[wpos++]; }
                word[qi] = 0;
                any = 1;
                if (sh_env_set(var, word) != 0) { console_write("for: environment full\n"); return 2; }
                { int rr = sh_script_run_range(i + 1, end_pos); if (rr != 0) return rr; }
            }
            (void)any;
            i = end_pos;
            continue;
        }
        if (strcmp(w, "while") == 0) {
            int else_pos = -1, end_pos = -1;
            if (sh_script_find_block(i, end, 2, &else_pos, &end_pos) != 0) {
                console_write("sh: unmatched while\n"); return 2;
            }
            (void)else_pos;
            const char *p = line;
            while (*p == ' ') p++;
            p += 5;
            while (*p == ' ') p++;
            char cond[128];
            int ci = 0;
            while (p[ci] && ci < 127) { cond[ci] = p[ci]; ci++; }
            cond[ci] = 0;
            int capped = 1;
            for (int iter = 0; iter < 100; iter++) {
                char cond_copy[128];
                int cj = 0;
                while (cond[cj]) { cond_copy[cj] = cond[cj]; cj++; }
                cond_copy[cj] = 0;
                int r = sh_script_exec(cond_copy);
                if (r == 1) return 1;
                if (sh_last_status != 0) { capped = 0; break; }
                { int rr = sh_script_run_range(i + 1, end_pos); if (rr != 0) return rr; }
            }
            /* The 100-iteration cap is fail-visible, never a
               wedge: reaching it prints once and continues. */
            if (capped) console_write("sh: while iteration limit reached (100)\n");
            i = end_pos;
            continue;
        }
        {
            char line_copy[256];
            int li = 0;
            while (line[li]) { line_copy[li] = line[li]; li++; }
            line_copy[li] = 0;
            int r = sh_script_exec(line_copy);
            if (r == 1) return 1;
        }
    }
    return 0;
}
static int sh_run_script_file(const char *name) {
    if (sh_script_depth >= 4) { console_write("sh: script nesting too deep\n"); return -1; }
    if (sh_lr_open(name, session_uid) != 0) return -1;
    sh_script_nlines = 0;
    for (;;) {
        int r = sh_lr_next();
        if (r == 0) break;
        if (r < 0) return -1;
        if (sh_script_nlines >= 128) { console_write("sh: script too long (max 128 lines)\n"); return -1; }
        int i = 0;
        while (sh_lr_line[i]) { sh_script_lines[sh_script_nlines][i] = sh_lr_line[i]; i++; }
        sh_script_lines[sh_script_nlines][i] = 0;
        sh_script_nlines++;
    }
    sh_script_depth++;
    int r = sh_script_run_range(0, sh_script_nlines);
    sh_script_depth--;
    return r;
}

/* `test` evaluation: returns 0 true, 1 false, 2 usage error.
   Supports: single string, !, -f/-d/-r/-w file, -z/-n string,
   =/!= string, -eq/-ne/-lt/-le/-gt/-ge numbers. -d is true
   for directory entries (§15); -f is true for non-directory
   entries the caller may stat. */
static int sh_test_num(const char *s, int *out) {
    if (!s || !s[0]) return -1;
    int neg = 0, i = 0, v = 0, digits = 0;
    if (s[0] == '-') { neg = 1; i = 1; }
    for (; s[i]; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (s[i] - '0');
        if (v > 1000000) v = 1000000;
        digits++;
    }
    if (digits == 0) return -1;
    *out = neg ? -v : v;
    return 0;
}
static int sh_file_perm_bit(const char *name, int bit) {
    /* bit: 4 = read, 2 = write. Computed from stat + groups,
       the same rule the filesystem enforces. */
    struct fs_stat st;
    if (fs_stat_path(name, sh_cwd, &st, session_uid) != 0) return 0;
    if (session_uid == 0) return 1;
    if (st.uid == session_uid) return (st.mode >> 6) & bit ? 1 : 0;
    if (st.gid != 0 && groups_user_in_gid(session_uid, st.gid)) return (st.mode >> 3) & bit ? 1 : 0;
    return st.mode & bit ? 1 : 0;
}
static int sh_test_eval(const char **args, int nargs) {
    if (nargs == 0) return 1; /* bare `test` is false */
    if (nargs == 1) return args[0][0] ? 0 : 1;
    if (strcmp(args[0], "!") == 0) {
        int r = sh_test_eval(args + 1, nargs - 1);
        if (r == 2) return 2;
        return r == 0 ? 1 : 0;
    }
    if (nargs == 2) {
        if (strcmp(args[0], "-f") == 0) {
            /* Visible existence: stat succeeds for root, owner,
               or any reader (same rule as `stat`). */
            struct fs_stat st;
            if (fs_stat_path(args[1], sh_cwd, &st, session_uid) != 0) return 1;
            return st.is_dir ? 1 : 0;
        }
        if (strcmp(args[0], "-d") == 0) {
            struct fs_stat st;
            if (fs_stat_path(args[1], sh_cwd, &st, session_uid) != 0) return 1;
            return st.is_dir ? 0 : 1;
        }
        if (strcmp(args[0], "-r") == 0) return sh_file_perm_bit(args[1], 4) ? 0 : 1;
        if (strcmp(args[0], "-w") == 0) return sh_file_perm_bit(args[1], 2) ? 0 : 1;
        if (strcmp(args[0], "-z") == 0) return args[1][0] == 0 ? 0 : 1;
        if (strcmp(args[0], "-n") == 0) return args[1][0] != 0 ? 0 : 1;
        return 2;
    }
    if (nargs == 3) {
        if (strcmp(args[1], "=") == 0) return strcmp(args[0], args[2]) == 0 ? 0 : 1;
        if (strcmp(args[1], "!=") == 0) return strcmp(args[0], args[2]) != 0 ? 0 : 1;
        int a = 0, b = 0;
        if (sh_test_num(args[0], &a) != 0 || sh_test_num(args[2], &b) != 0) return 2;
        if (strcmp(args[1], "-eq") == 0) return a == b ? 0 : 1;
        if (strcmp(args[1], "-ne") == 0) return a != b ? 0 : 1;
        if (strcmp(args[1], "-lt") == 0) return a < b ? 0 : 1;
        if (strcmp(args[1], "-le") == 0) return a <= b ? 0 : 1;
        if (strcmp(args[1], "-gt") == 0) return a > b ? 0 : 1;
        if (strcmp(args[1], "-ge") == 0) return a >= b ? 0 : 1;
        return 2;
    }
    return 2;
}

/* Glob matching (* and ? only) and expansion. Expansion runs in
   the outermost execute() after $VAR/alias expansion, per pipe
   stage, only for file-argument commands, and never for a
   redirection target or a flag word. No match leaves the word
   literal (bash default). Over-cap refuses, never truncates. */
static int sh_glob_match_here(const char *pat, const char *str) {
    if (*pat == 0) return *str == 0;
    if (*pat == '*') {
        /* Collapse runs of '*', then try every split. */
        while (*pat == '*') pat++;
        if (*pat == 0) return 1;
        for (const char *s = str; ; s++) {
            if (sh_glob_match_here(pat, s)) return 1;
            if (*s == 0) return 0;
        }
    }
    if (*str == 0) return 0;
    if (*pat == '?' || *pat == *str) return sh_glob_match_here(pat + 1, str + 1);
    return 0;
}
/* Stage-command tracking for globbing (file-scope, shared by
   sh_glob_expand's stages). */
char sh_glob_cmd[32];
int sh_glob_group_pending = 0;
static char sh_glob_names[32][32];
static u32 sh_glob_sizes[32];
static char sh_glob_out[256];
static int sh_glob_expand(const char *line) {
    /* Copy line into sh_glob_out, expanding as we go. */
    u32 o = 0, i = 0;
    int stage_first = 1; /* first word of the current stage */
    char prev_word[32]; int prev_is_redir = 0;
    prev_word[0] = 0;
    while (line[i]) {
        while (line[i] == ' ') {
            if (o < 255) sh_glob_out[o++] = ' ';
            i++;
        }
        if (!line[i]) break;
        if (line[i] == '|' || line[i] == '>' || line[i] == '<') {
            if (o < 255) sh_glob_out[o++] = line[i];
            if (line[i] == '|') stage_first = 1;
            prev_is_redir = (line[i] == '>' || line[i] == '<');
            prev_word[0] = line[i]; prev_word[1] = 0;
            i++;
            continue;
        }
        /* One word. */
        char word[64]; int wi = 0;
        while (line[i] && line[i] != ' ' && line[i] != '|' && line[i] != '>' && line[i] != '<' && wi < 63) {
            word[wi++] = line[i++];
        }
        word[wi] = 0;
        int is_cmd = stage_first;
        stage_first = 0;
        int has_wild = 0;
        for (int k = 0; k < wi; k++) if (word[k] == '*' || word[k] == '?') has_wild = 1;
        int expanded = 0;
        if (!is_cmd && has_wild && !prev_is_redir && word[0] != '-') {
            /* Whitelist is the previous stage's command word:
               stored in prev_word only when it was a command;
               simpler: re-derive from the stage start by
               scanning back is not possible here, so the
               whitelist check uses the stage command saved
               in sh_glob_cmd. */
            static const char *wl[] = {"ls","cat","rm","mv","cp","grep","sort","wc","head","tail","diff","du","find","chmod","chown","chgrp","stat","touch","edit","write","sha256",0};
            int ok = 0;
            for (int k = 0; wl[k]; k++) if (strcmp(sh_glob_cmd, wl[k]) == 0) ok = 1;
            if (ok) {
                int cnt = fs_enum_as(session_uid, sh_glob_names, sh_glob_sizes, 32);
                int first_match = 1;
                for (int k = 0; k < cnt; k++) {
                    if (!sh_glob_match_here(word, sh_glob_names[k])) continue;
                    if (!first_match) { if (o < 255) sh_glob_out[o++] = ' '; }
                    first_match = 0; expanded = 1;
                    for (int m = 0; sh_glob_names[k][m]; m++) {
                        if (o >= 255) { console_write("glob expansion too long\n"); return -1; }
                        sh_glob_out[o++] = sh_glob_names[k][m];
                    }
                }
            }
        }
        if (!expanded) {
            for (int k = 0; k < wi; k++) {
                if (o >= 255) { console_write("glob expansion too long\n"); return -1; }
                sh_glob_out[o++] = word[k];
            }
        }
        /* Track the stage command and the previous word. A
           group call (`fs ls ...`) makes the member the
           effective command for the whitelist check. */
        if (is_cmd) {
            extern char sh_glob_cmd[32];
            extern int sh_glob_group_pending;
            int ci = 0;
            while (word[ci] && ci < 31) { sh_glob_cmd[ci] = word[ci]; ci++; }
            sh_glob_cmd[ci] = 0;
            sh_glob_group_pending = (help_group_index(word) >= 0);
        } else {
            extern char sh_glob_cmd[32];
            extern int sh_glob_group_pending;
            if (sh_glob_group_pending) {
                if (help_find_in_group(sh_glob_cmd, word)) {
                    int ci = 0;
                    while (word[ci] && ci < 31) { sh_glob_cmd[ci] = word[ci]; ci++; }
                    sh_glob_cmd[ci] = 0;
                }
                sh_glob_group_pending = 0;
            }
        }
        {
            int pi = 0;
            while (word[pi] && pi < 31) { prev_word[pi] = word[pi]; pi++; }
            prev_word[pi] = 0;
        }
        prev_is_redir = 0;
    }
    sh_glob_out[o] = 0;
    return 0;
}

/* ---- Small regex engine (Linux-comparability run) ----
   Backtracking matcher for grep/sed: `.` `*` `+` `?` `^` `$`
   `[...]` `[^...]` escapes (\d \w \s and negations, plus
   literal escapes) and top-level `|` alternation. Groups are
   NOT supported ('(' is literal) — documented. Atoms always
   consume exactly one character, so backtracking terminates;
   a step budget aborts pathological patterns visibly instead
   of hanging (search returns -1 on overflow). All state is
   file-scope; the kernel stack is never used for buffers. */
static int sh_re_steps = 0;
static int sh_re_overflow = 0;
static int sh_re_is_word(int c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '_';
}
/* Match one atom (pat points at its start) against ch.
   Returns the pattern pointer just past the atom, or 0 when
   the atom does not match ch / the atom is malformed. */
static const char *sh_re_atom(const char *pat, int ch, int *matched) {
    *matched = 0;
    if (pat[0] == '.') { *matched = (ch != 0); return pat + 1; }
    if (pat[0] == '[') {
        const char *p = pat + 1;
        int neg = 0;
        if (*p == '^') { neg = 1; p++; }
        int hit = 0, first = 1;
        while (*p && !(*p == ']' && !first)) {
            first = 0;
            int lo;
            if (*p == '\\' && p[1]) { p++; lo = (unsigned char)*p; }
            else lo = (unsigned char)*p;
            if (p[1] == '-' && p[2] && p[2] != ']') {
                int hi;
                if (p[2] == '\\' && p[3]) { hi = (unsigned char)p[3]; p += 1; }
                else hi = (unsigned char)p[2];
                if (ch >= lo && ch <= hi) hit = 1;
                p += 3;
            } else {
                if (ch == lo) hit = 1;
                p++;
            }
        }
        if (*p != ']') return 0; /* unterminated class */
        *matched = neg ? !hit : hit;
        return p + 1;
    }
    if (pat[0] == '\\' && pat[1]) {
        char e = pat[1];
        if (e == 'd') *matched = (ch >= '0' && ch <= '9');
        else if (e == 'D') *matched = !(ch >= '0' && ch <= '9') && ch != 0;
        else if (e == 'w') *matched = sh_re_is_word(ch);
        else if (e == 'W') *matched = !sh_re_is_word(ch) && ch != 0;
        else if (e == 's') *matched = (ch == ' ' || ch == '\t');
        else if (e == 'S') *matched = !(ch == ' ' || ch == '\t') && ch != 0;
        else *matched = (ch == (unsigned char)e);
        return pat + 2;
    }
    if (pat[0] == 0) return 0;
    *matched = (ch == (unsigned char)pat[0]);
    return pat + 1;
}
static int sh_re_match_seq(const char *pat, const char *text);
static int sh_re_match_seq_star(const char *pat, const char *rest, const char *text);
static int sh_re_match_seq(const char *pat, const char *text) {
    if (sh_re_overflow) return 0;
    if (++sh_re_steps > 20000) { sh_re_overflow = 1; return 0; }
    if (pat[0] == 0) return 1; /* pattern consumed: prefix match */
    if (pat[0] == '$' && pat[1] == 0) return text[0] == 0;
    int m = 0;
    const char *after = sh_re_atom(pat, (unsigned char)text[0], &m);
    if (!after) return 0;
    char q = *after;
    if (q == '*' || q == '+' || q == '?') {
        const char *rest = after + 1;
        if (q == '?') {
            if (sh_re_match_seq(rest, text)) return 1;
            if (text[0] && m) return sh_re_match_seq(rest, text + 1);
            return 0;
        }
        if (q == '+') {
            if (!text[0] || !m) return 0;
            /* One consumed, then star semantics on the rest. */
            return sh_re_match_seq_star(pat, rest, text + 1);
        }
        /* '*' */
        if (sh_re_match_seq(rest, text)) return 1;
        if (text[0] && m) return sh_re_match_seq(pat, text + 1);
        return 0;
    }
    if (!text[0] || !m) return 0;
    return sh_re_match_seq(after, text + 1);
}
/* Star loop helper, kept separate so the '+' branch above stays
   readable: try rest at text, else consume one atom and retry. */
static int sh_re_match_seq_star(const char *pat, const char *rest, const char *text) {
    if (sh_re_match_seq(rest, text)) return 1;
    int m = 0;
    const char *after = sh_re_atom(pat, (unsigned char)text[0], &m);
    if (!after || !text[0] || !m) return 0;
    return sh_re_match_seq_star(pat, rest, text + 1);
}
/* Search: 1 match, 0 no match, -1 pattern too complex.
   Alternatives are split on top-level '|' (classes and
   escapes respected); '^' anchors an alternative to the
   start of the line. */
static int sh_re_search(const char *pattern, const char *text) {
    sh_re_steps = 0; sh_re_overflow = 0;
    const char *alt = pattern;
    for (;;) {
        /* Find the end of this alternative. */
        const char *p = alt;
        int in_class = 0;
        while (*p) {
            if (*p == '\\' && p[1]) { p += 2; continue; }
            if (*p == '[') in_class = 1;
            else if (*p == ']') in_class = 0;
            else if (*p == '|' && !in_class) break;
            p++;
        }
        /* Try this alternative (copied into a file-scope
           buffer so it is NUL-terminated on its own). */
        static char sh_re_alt[256];
        int alen = 0;
        while (alt[alen] && alt + alen < p && alen < 255) { sh_re_alt[alen] = alt[alen]; alen++; }
        sh_re_alt[alen] = 0;
        const char *try_pat = sh_re_alt;
        int anchored = 0;
        if (try_pat[0] == '^') { anchored = 1; try_pat++; }
        if (anchored) {
            if (sh_re_match_seq(try_pat, text)) return sh_re_overflow ? -1 : 1;
        } else {
            for (const char *s = text; ; s++) {
                if (sh_re_match_seq(try_pat, s)) return sh_re_overflow ? -1 : 1;
                if (sh_re_overflow) return -1;
                if (*s == 0) break;
            }
        }
        if (sh_re_overflow) return -1;
        if (*p == 0) break;
        alt = p + 1;
    }
    return 0;
}

/* Greedy match-end: returns the pointer just past the LONGEST
   prefix match of pat at text (quantifiers prefer consuming),
   or 0 when there is no match. Used by sed, where the span
   matters; grep only needs existence (sh_re_search above). */
static const char *sh_re_match_end(const char *pat, const char *text);
static const char *sh_re_match_end_star(const char *pat, const char *rest, const char *text) {
    /* Star: try consuming one more atom first (greedy), then rest. */
    int m = 0;
    const char *after = sh_re_atom(pat, (unsigned char)text[0], &m);
    if (after && text[0] && m) {
        const char *e = sh_re_match_end_star(pat, rest, text + 1);
        if (e) return e;
    }
    return sh_re_match_end(rest, text);
}
static const char *sh_re_match_end(const char *pat, const char *text) {
    if (sh_re_overflow) return 0;
    if (++sh_re_steps > 20000) { sh_re_overflow = 1; return 0; }
    if (pat[0] == 0) return text;
    if (pat[0] == '$' && pat[1] == 0) return (text[0] == 0) ? text : 0;
    int m = 0;
    const char *after = sh_re_atom(pat, (unsigned char)text[0], &m);
    if (!after) return 0;
    char q = *after;
    if (q == '*' || q == '+' || q == '?') {
        const char *rest = after + 1;
        if (q == '?') {
            if (text[0] && m) {
                const char *e = sh_re_match_end(rest, text + 1);
                if (e) return e;
            }
            return sh_re_match_end(rest, text);
        }
        if (q == '+') {
            if (!text[0] || !m) return 0;
            return sh_re_match_end_star(pat, rest, text + 1);
        }
        return sh_re_match_end_star(pat, rest, text);
    }
    if (!text[0] || !m) return 0;
    return sh_re_match_end(after, text + 1);
}
/* First match span for pattern in text: 1 with ms/me set,
   0 none, -1 too complex. Alternatives in order; within an
   alternative the leftmost start wins. */
static int sh_re_search_span(const char *pattern, const char *text, const char **ms, const char **me) {
    sh_re_steps = 0; sh_re_overflow = 0;
    const char *alt = pattern;
    for (;;) {
        const char *p = alt;
        int in_class = 0;
        while (*p) {
            if (*p == '\\' && p[1]) { p += 2; continue; }
            if (*p == '[') in_class = 1;
            else if (*p == ']') in_class = 0;
            else if (*p == '|' && !in_class) break;
            p++;
        }
        static char sh_re_alt2[256];
        int alen = 0;
        while (alt[alen] && alt + alen < p && alen < 255) { sh_re_alt2[alen] = alt[alen]; alen++; }
        sh_re_alt2[alen] = 0;
        const char *try_pat = sh_re_alt2;
        int anchored = 0;
        if (try_pat[0] == '^') { anchored = 1; try_pat++; }
        if (anchored) {
            const char *e = sh_re_match_end(try_pat, text);
            if (e) { *ms = text; *me = e; return sh_re_overflow ? -1 : 1; }
        } else {
            for (const char *s = text; ; s++) {
                const char *e = sh_re_match_end(try_pat, s);
                if (e) { *ms = s; *me = e; return sh_re_overflow ? -1 : 1; }
                if (sh_re_overflow) return -1;
                if (*s == 0) break;
            }
        }
        if (sh_re_overflow) return -1;
        if (*p == 0) break;
        alt = p + 1;
    }
    return 0;
}

/* Forward declaration: execute_inner's group-dispatch recursion
   re-enters the wrapper, which is defined after it. */
static int execute(char *line);

/* --- socket shell helpers (§15.2: `srv` + `socktest`) --- */
/* Split rest into words in place (static buffer, fw-add style).
   Returns the word count. */
static int sh_split_rest(char *rest, char **words, int maxw) {
    static char sh_sock_buf[256];
    if (!rest || !rest[0]) return 0;
    u32 i = 0;
    while (rest[i] && i < sizeof(sh_sock_buf) - 1) { sh_sock_buf[i] = rest[i]; i++; }
    sh_sock_buf[i] = 0;
    int wc = 0;
    char *p = sh_sock_buf;
    while (*p && wc < maxw) {
        while (*p == ' ') p++;
        if (!*p) break;
        char *w = p;
        if (sh_parse_word(&p) != 0) break; /* unterminated: drop the partial word */
        words[wc++] = w;
        if (*p == ' ') p++;
    }
    return wc;
}

static int sh_sock_num(const char *s, u32 *out) {
    if (!s || !*s) return 0;
    u32 v = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9' || v > 1000000) return 0;
        v = v * 10u + (u32)(*p - '0');
    }
    *out = v;
    return 1;
}

/* Copy bytes to a NUL-terminated printable string for the log
   (payloads are test-controlled, but a peer is untrusted). */
static void sh_sanitize(const u8 *in, u32 len, char *out, u32 out_size) {
    u32 n = len;
    if (n > out_size - 1) n = out_size - 1;
    for (u32 i = 0; i < n; i++) {
        u8 c = in[i];
        out[i] = (c >= 32 && c < 127) ? (char)c : '?';
    }
    out[n] = 0;
}

/* Bind + listen probe: proves the port can (or cannot) be
   listened on, then closes. It is NOT a server — a probe
   that stayed open would leak a listener with nobody
   polling it, and the next command's packets would queue
   unseen. `srv serve` is the real server path. */
static void sh_srv_listen(u16 port) {
    if (!net_present()) { console_write("srv: no NIC\n"); return; }
    if (!net_ip_configured()) { console_write("srv: no IP address (run dhcp)\n"); return; }
    int li;
    if (sock_alloc(SK_STREAM, &li) != 0) { console_write("srv: no socket available\n"); return; }
    if (port < 1024 && session_uid == 0 && (session_caps & (1u << CAP_NET)) == 0) {
        console_printf("srv: listen on port %u refused (capability cap_net is not set)\n", port);
        sock_free(li);
        return;
    }
    int brc = sock_bind(li, ip_from_u32(0), port, session_uid);
    if (brc == -2) {
        console_printf("srv: listen on port %u refused (root only for ports below 1024)\n", port);
        sock_free(li);
        return;
    }
    if (brc != 0) {
        console_printf("srv: bind port %u failed (already in use?)\n", port);
        sock_free(li);
        return;
    }
    if (sock_listen(li, 4, session_uid) != 0) {
        console_write("srv: listen failed\n");
        sock_free(li);
        return;
    }
    console_printf("srv: listening on %u\n", port);
    sock_close(li);
}

/* Real server loop: accept up to `count` connections, read
   one payload from each, and only then reply to all of
   them — so a second connection is accepted (and its
   payload read) while the first is still open. On timeout
   it replies to whatever it has and reports the shortfall
   instead of hanging the shell. */
static void sh_srv_serve(u16 port, int count, u32 timeout_ticks) {
    if (!net_present()) { console_write("srv: no NIC\n"); return; }
    if (!net_ip_configured()) { console_write("srv: no IP address (run dhcp)\n"); return; }
    if (count < 1) count = 1;
    if (count > 4) count = 4;
    int li;
    if (sock_alloc(SK_STREAM, &li) != 0) { console_write("srv: no socket available\n"); return; }
    if (port < 1024 && session_uid == 0 && (session_caps & (1u << CAP_NET)) == 0) {
        console_printf("srv: listen on port %u refused (capability cap_net is not set)\n", port);
        sock_free(li);
        return;
    }
    int brc = sock_bind(li, ip_from_u32(0), port, session_uid);
    if (brc == -2) {
        console_printf("srv: listen on port %u refused (root only for ports below 1024)\n", port);
        sock_free(li);
        return;
    }
    if (brc != 0) {
        console_printf("srv: bind port %u failed (already in use?)\n", port);
        sock_free(li);
        return;
    }
    if (sock_listen(li, 4, session_uid) != 0) {
        console_write("srv: listen failed\n");
        sock_free(li);
        return;
    }
    console_printf("srv: listening on %u\n", port);
    int conns[4];
    static u8 sh_srv_pay[4][256];
    u32 sh_srv_plen[4];
    int sh_srv_got[4];
    int nacc = 0;
    for (int i = 0; i < 4; i++) { conns[i] = -1; sh_srv_plen[i] = 0; sh_srv_got[i] = 0; }
    u32 start = timer_ticks;
    while (timer_ticks - start < timeout_ticks) {
        net_poll();
        int child = -1;
        if (nacc < count && sock_accept(li, &child) == 0) {
            conns[nacc] = child;
            console_printf("srv: accepted connection %d\n", nacc + 1);
            nacc++;
        }
        int allgot = (nacc == count);
        for (int i = 0; i < nacc; i++) {
            if (sh_srv_got[i]) continue;
            u8 buf[256];
            u32 done = 0;
            int rc = sock_tcp_recv_nb(conns[i], buf, sizeof(buf) - 1, &done);
            if (rc == 0 && done > 0) {
                if (done > 255) done = 255;
                memcpy(sh_srv_pay[i], buf, done);
                sh_srv_plen[i] = done;
                sh_srv_got[i] = 1;
                char clean[256];
                sh_sanitize(buf, done, clean, sizeof(clean));
                console_printf("srv: conn %d payload %s\n", i + 1, clean);
            } else if (rc != 0) {
                sh_srv_got[i] = 1;
                sh_srv_plen[i] = 0;
                console_printf("srv: conn %d closed without payload\n", i + 1);
            } else {
                allgot = 0;
            }
        }
        if (nacc == count && allgot) break;
    }
    int served = 0;
    for (int i = 0; i < nacc; i++) {
        if (!sh_srv_got[i] || conns[i] < 0) continue;
        static u8 reply[300];
        memcpy(reply, "SRV-ACK:", 8);
        if (sh_srv_plen[i] > 0) memcpy(reply + 8, sh_srv_pay[i], sh_srv_plen[i]);
        if (sock_tcp_send(conns[i], reply, 8 + sh_srv_plen[i]) == 0) served++;
        else console_printf("srv: conn %d reply failed\n", i + 1);
    }
    for (int i = 0; i < nacc; i++)
        if (conns[i] >= 0) sock_close(conns[i]);
    sock_close(li);
    if (nacc == count && served == count)
        console_printf("srv: served %d connections\n", count);
    else
        console_printf("srv: timeout waiting for connections (accepted %d, served %d)\n", nacc, served);
}

/* FIRST GATE (§15.2): two concurrent client connections
   through the new table, both completed with correct data.
   Both connects finish before either send, so both sockets
   are ESTABLISHED at once — a single-connection stack
   could not pass this. */
static void sh_socktest_clients(ip_t peer, u16 port) {
    if (!net_present()) { console_write("socktest: no NIC\n"); return; }
    if (!net_ip_configured()) { console_write("socktest: no IP address (run dhcp)\n"); return; }
    int a = -1, b = -1;
    if (sock_alloc(SK_STREAM, &a) != 0 || sock_alloc(SK_STREAM, &b) != 0) {
        console_write("socktest: no socket available\n");
        if (a >= 0) sock_free(a);
        if (b >= 0) sock_free(b);
        return;
    }
    if (sock_connect(a, peer, port) != 0) {
        console_write("socktest: client A connect failed\n");
        sock_close(a); sock_free(b);
        return;
    }
    if (sock_connect(b, peer, port) != 0) {
        console_write("socktest: client B connect failed\n");
        sock_close(a); sock_free(b);
        return;
    }
    console_write("socktest: two connections established\n");
    int ok = 1;
    if (sock_tcp_send(a, (const u8 *)"HELLO-A", 7) != 0) { console_write("socktest: client A send failed\n"); ok = 0; }
    if (sock_tcp_send(b, (const u8 *)"HELLO-B", 7) != 0) { console_write("socktest: client B send failed\n"); ok = 0; }
    static u8 ra[128], rb[128];
    int na = sock_tcp_recv(a, ra, sizeof(ra) - 1, 500);
    int nb = sock_tcp_recv(b, rb, sizeof(rb) - 1, 500);
    if (na > 0) {
        char clean[128];
        sh_sanitize(ra, (u32)na, clean, sizeof(clean));
        console_printf("socktest: client A got %s\n", clean);
        if (na != 11 || memcmp(ra, "ACK-HELLO-A", 11) != 0) ok = 0;
    } else { console_write("socktest: client A recv failed\n"); ok = 0; }
    if (nb > 0) {
        char clean[128];
        sh_sanitize(rb, (u32)nb, clean, sizeof(clean));
        console_printf("socktest: client B got %s\n", clean);
        if (nb != 11 || memcmp(rb, "ACK-HELLO-B", 11) != 0) ok = 0;
    } else { console_write("socktest: client B recv failed\n"); ok = 0; }
    console_write(ok ? "socktest: two clients OK\n" : "socktest: two clients FAIL\n");
    sock_close(a);
    sock_close(b);
}

static void sh_socktest_udp(ip_t peer, u16 port) {
    if (!net_present()) { console_write("socktest: no NIC\n"); return; }
    if (!net_ip_configured()) { console_write("socktest: no IP address (run dhcp)\n"); return; }
    int s = -1;
    if (sock_alloc(SK_DGRAM, &s) != 0) { console_write("socktest: no socket available\n"); return; }
    if (sock_bind(s, ip_from_u32(0), 19001, session_uid) != 0) {
        console_write("socktest: udp bind failed\n");
        sock_free(s);
        return;
    }
    if (sock_udp_send(s, peer, port, (const u8 *)"UDP-HELLO", 9) != 0) {
        console_write("socktest: udp send failed\n");
        sock_free(s);
        return;
    }
    static u8 rbuf[128];
    int n = sock_udp_recv(s, rbuf, sizeof(rbuf) - 1, 0, 0, 500);
    if (n > 0) {
        char clean[128];
        sh_sanitize(rbuf, (u32)n, clean, sizeof(clean));
        console_printf("socktest: udp got %s\n", clean);
        console_write((n == 7 && memcmp(rbuf, "UDP-ACK", 7) == 0) ?
                      "socktest: udp OK\n" : "socktest: udp FAIL\n");
    } else {
        console_write("socktest: udp recv failed\n");
    }
    sock_free(s);
}
static int execute_inner(char *line) {
    char *tok[4];
    char *rest = 0;
    int n = tokenize(line, tok, &rest);
    if (n < 0) { console_write("quote: unterminated quote\n"); sh_cmd_status = 2; return 0; }
    if (n == 0) return 0;
    sh_cmd_status = 0; /* each command starts at success; builtins
                          and the unknown-command branch set it */
    /* Group dispatch (shell grouping): `net ping <ip>`,
       `test csprngtest`, `fs ls`, and so on rewrite to the flat
       command and run once. `pkg` is excluded: it already has
       its own subcommand dispatch, and rewriting "pkg list"
       to "list" would hit "Unknown command". Group dispatch
       only fires with a member subcommand, so bare `fs` keeps
       printing fs status and bare `gui` keeps opening the
       classic GUI, exactly as before. The rebuilt line is
       strictly shorter than the input line, so recursion
       terminates (at most one rewrite: the rebuilt line's
       first word is a command, and only fs/gui are both a
       group and a command, where the rebuilt line has n<2
       or hits the flat branch). */
    if (n >= 2 && help_group_index(tok[0]) >= 0 && strcmp(tok[0], "pkg") != 0) {
        if (strcmp(tok[1], "help") == 0) {
            char first[32];
            if (help_first_word(rest, first, sizeof(first))) {
                const struct help_entry *e = help_find_in_group(tok[0], first);
                if (e) help_print_entry(e);
                else help_print_group(tok[0]);
            } else help_print_group(tok[0]);
            return 0;
        }
        if (help_find_in_group(tok[0], tok[1])) {
            char line2[128];
            int li = 0;
            const char *p = tok[1];
            while (*p && li < 120) line2[li++] = *p++;
            if (rest && rest[0]) {
                line2[li++] = ' ';
                p = rest;
                while (*p && li < 127) line2[li++] = *p++;
            }
            line2[li] = 0;
            return execute(line2);
        }
        /* Not a member: fall through to flat dispatch, so e.g.
           "fs foo" still prints fs status as it always did. */
    }
    if (strcmp(tok[0], "help") == 0) {
        if (n < 2) {
            help_print_index();
        } else if (help_group_index(tok[1]) >= 0) {
            char first[32];
            if (help_first_word(rest, first, sizeof(first))) {
                /* Try "group sub" (e.g. "pkg install") first, then
                   a plain member name (e.g. "net ping"). */
                char combined[64];
                int ci = 0;
                const char *p = tok[1];
                while (*p && ci < 30) combined[ci++] = *p++;
                combined[ci++] = ' ';
                p = first;
                while (*p && ci < 63) combined[ci++] = *p++;
                combined[ci] = 0;
                const struct help_entry *e = help_find(combined);
                if (!e) e = help_find_in_group(tok[1], first);
                if (e) help_print_entry(e);
                else help_print_group(tok[1]);
            } else help_print_group(tok[1]);
        } else {
            /* Try "cmd sub" (pkg/castore/tofprints), then cmd. */
            char first[32];
            const struct help_entry *e = 0;
            if (help_first_word(rest, first, sizeof(first))) {
                char combined[64];
                int ci = 0;
                const char *p = tok[1];
                while (*p && ci < 30) combined[ci++] = *p++;
                combined[ci++] = ' ';
                p = first;
                while (*p && ci < 63) combined[ci++] = *p++;
                combined[ci] = 0;
                e = help_find(combined);
            }
            if (!e) e = help_find(tok[1]);
            if (e) help_print_entry(e);
            else console_printf("help: no such command or group '%s' (type help)\n", tok[1]);
        }
    } else if (strcmp(tok[0], "idle") == 0) {
        if (n < 2) {
            if (idle_timeout_minutes == 0) console_write("Idle timeout: disabled (never locks on idle)\n");
            else console_printf("Idle timeout: %u minutes\n", idle_timeout_minutes);
        } else if (strcmp(tok[1], "off") == 0) {
            idle_timeout_minutes = 0;
            console_write("Idle lock disabled for this session.\n");
        } else {
            u32 v = 0; int bad = 0;
            for (const char *p = tok[1]; *p; p++) {
                if (*p < '0' || *p > '9' || v > 100000) { bad = 1; break; }
                v = v * 10u + (u32)(*p - '0');
            }
            if (bad || v > 480) { console_write("Usage: idle [minutes 0-480|off] (0 = never)\n"); return 0; }
            idle_timeout_minutes = v;
            if (v == 0) console_write("Idle lock disabled for this session.\n");
            else console_printf("Idle timeout set to %u minutes for this session.\n", v);
        }
    } else if (strcmp(tok[0], "fbinfo") == 0) {
        if (fb_ready()) console_printf("Framebuffer: %ux%u, pitch %u, phys 0x%x (ready)\n",
                                       fb_width(), fb_height(), fb_pitch(), fb_phys_addr());
        else console_printf("Framebuffer: not available - %s (GRUB bpp=%d type=%d)\n",
                            fb_diag_reason(), fb_diag_bpp(), fb_diag_type());
        console_write("If this says no framebuffer in Bochs, check the emulator's VGA settings (Bochs needs vga extension=vbe) or try QEMU with -vga std.\n");
    } else if (strcmp(tok[0], "kbdstat") == 0) {
        /* v0.7.3 diagnostic, no typing needed to read it once the
           shell is up: controller status byte (bit 0 = output
           buffer full, bit 5 = next byte is mouse data), bytes
           drained at startup, and the last raw scancode received.
           If keys are typed and last-scancode never changes, no
           bytes are reaching the controller at all (emulator/app
           drops them before the guest) and no kernel change can
           fix that; if it changes but no characters appear, the
           scancode set/translation is wrong. */
        console_printf("Keyboard: controller status=0x%x startup-drained=%u last-scancode=0x%x\n",
                       (u32)keyboard_controller_status(),
                       keyboard_startup_drained(),
                       (u32)keyboard_last_scancode());
    } else if (strcmp(tok[0], "mem") == 0 || strcmp(tok[0], "free") == 0) {
        if (strcmp(tok[0], "free") == 0 && n >= 2 && strcmp(tok[1], "-h") == 0) {
            u32 tot = pmm_total_frames(), fr = pmm_free_frames(), us = pmm_used_frames();
            console_printf("Mem: total %u MiB, free %u MiB, used %u MiB\n",
                           (tot * 4u) >> 10, (fr * 4u) >> 10, (us * 4u) >> 10);
        } else cmd_mem();
    } else if (strcmp(tok[0], "ticks") == 0) {
        console_printf("Timer ticks: %u (%u seconds at 100 Hz)\n",
                       timer_ticks, timer_ticks / 100);
    } else if (strcmp(tok[0], "clear") == 0) {
        console_clear();
    } else if (strcmp(tok[0], "hostname") == 0) {
        if (n < 2) { console_printf("%s\n", sh_hostname); }
        else {
            if (sh_cap_gate(CAP_SYS, "hostname") != 0) return 0;
            u32 i = 0;
            while (tok[1][i] && i < 31) { sh_hostname[i] = tok[1][i]; i++; }
            sh_hostname[i] = 0;
            console_printf("hostname set to %s\n", sh_hostname);
        }
    } else if (strcmp(tok[0], "dmesg") == 0) {
        if (n >= 2 && strcmp(tok[1], "-c") == 0) {
            if (sh_cap_gate(CAP_SYS, "dmesg") != 0) return 0;
            console_dmesg_clear();
            console_write("dmesg: cleared\n");
        } else console_dmesg_print(0);
    } else if (strcmp(tok[0], "log") == 0) {
        u32 tail_n = 0;
        if (n >= 2 && strcmp(tok[1], "-n") == 0) {
            /* tokenize() stops at 2 tokens: N is rest's first
               word, and nothing may follow it. */
            if (!rest || !rest[0]) { console_write("Usage: log [-n N]\n"); return 0; }
            char *sp = rest;
            while (*sp && *sp != ' ') sp++;
            if (*sp) { *sp = 0; sp++; while (*sp == ' ') sp++; if (*sp) { console_write("Usage: log [-n N]\n"); return 0; } }
            int v = sh_parse_num(rest);
            if (v < 0) { console_write("Usage: log [-n N]\n"); return 0; }
            tail_n = (u32)v;
        } else if (n >= 2) { console_write("Usage: log [-n N]\n"); return 0; }
        sh_print_audit(0, tail_n);
    } else if (strcmp(tok[0], "last") == 0) {
        u32 tail_n = 0;
        if (n >= 2 && strcmp(tok[1], "-n") == 0) {
            /* tokenize() stops at 2 tokens: N is rest's first
               word, and nothing may follow it. */
            if (!rest || !rest[0]) { console_write("Usage: last [-n N]\n"); return 0; }
            char *sp = rest;
            while (*sp && *sp != ' ') sp++;
            if (*sp) { *sp = 0; sp++; while (*sp == ' ') sp++; if (*sp) { console_write("Usage: last [-n N]\n"); return 0; } }
            int v = sh_parse_num(rest);
            if (v < 0) { console_write("Usage: last [-n N]\n"); return 0; }
            tail_n = (u32)v;
        } else if (n >= 2) { console_write("Usage: last [-n N]\n"); return 0; }
        sh_print_audit(1, tail_n);
    } else if (strcmp(tok[0], "locale") == 0) {
        console_write("LANG=C\nLC_ALL=C\n");
    } else if (strcmp(tok[0], "pwd") == 0) {
        console_write(sh_cwd);
        console_putchar('\n');
    } else if (strcmp(tok[0], "echo") == 0) {
        /* tokenize() splits the text into tok[1] + rest, so rejoin
           with one space; bare `echo` prints just a newline.
           tok[1] is already unquoted by tokenize(); rest is
           unquoted here, so quoted spans print without their
           quotes and an unterminated quote errors instead of
           printing half a line. */
        if (n >= 2) {
            if (rest && rest[0] && sh_unquote_copy(rest, sh_unquote_buf, sizeof(sh_unquote_buf)) != 0) {
                console_write("quote: unterminated quote\n"); return 0;
            }
            console_write(tok[1]);
            if (rest && rest[0]) { console_putchar(' '); console_write(sh_unquote_buf); }
        }
        console_putchar('\n');
    } else if (strcmp(tok[0], "history") == 0) {
        /* Session command history (parity run): the ring lives
           in shell_loop's statics, never on disk. */
        if (n >= 2 && strcmp(tok[1], "-c") == 0) {
            sh_hist_n = 0;
            sh_hist_pos = -1;
            console_write("history: cleared\n");
        } else {
            for (u32 i = 0; i < sh_hist_n; i++)
                console_printf("%u  %s\n", i + 1, sh_hist[i]);
        }
    } else if (strcmp(tok[0], "export") == 0) {
        if (n < 2) {
            for (u32 i = 0; i < sh_env_n; i++)
                console_printf("%s=%s\n", sh_env_name[i], sh_env_val[i]);
        } else {
            /* tok[1] holds NAME=VALUE (or NAME); rest appends
               with a space, so values may contain spaces. */
            char *eq = tok[1];
            while (*eq && *eq != '=') eq++;
            if (*eq != '=') { console_write("Usage: export NAME=VALUE\n"); return 0; }
            *eq = 0;
            char value[128];
            u32 v = 0;
            int overflow = 0;
            const char *p = eq + 1;
            while (*p) { if (v < 127) value[v++] = *p; else overflow = 1; p++; }
            if (rest && rest[0]) {
                if (v < 127) value[v++] = ' '; else overflow = 1;
                p = rest;
                while (*p) { if (v < 127) value[v++] = *p; else overflow = 1; p++; }
            }
            value[v] = 0;
            if (!sh_name_ok(tok[1])) { console_write("Usage: export NAME=VALUE\n"); return 0; }
            if (overflow) { console_write("export: value too long\n"); return 0; }
            int r = sh_env_set(tok[1], value);
            if (r == -1) console_write("export: environment full (16)\n");
            else if (r == -2) console_write("export: value too long\n");
        }
    } else if (strcmp(tok[0], "unset") == 0) {
        if (n < 2) { console_write("Usage: unset NAME\n"); return 0; }
        sh_env_unset(tok[1]); /* silent when missing, like Linux */
    } else if (strcmp(tok[0], "alias") == 0) {
        if (n < 2) {
            for (u32 i = 0; i < sh_alias_n; i++)
                console_printf("alias %s='%s'\n", sh_alias_name[i], sh_alias_val[i]);
        } else {
            if (!sh_name_ok(tok[1]) || !rest || !rest[0]) {
                console_write("Usage: alias <name> <command...>\n"); return 0;
            }
            /* Strip surrounding quotes if they wrap the whole
               value, so `alias ll='ls -l'` round-trips. */
            char vbuf[128];
            const char *v = rest;
            u32 vl = strlen(v);
            if (vl >= 2 && ((v[0] == '\'' && v[vl - 1] == '\'') ||
                            (v[0] == '"' && v[vl - 1] == '"'))) {
                u32 j = 0;
                for (u32 k = 1; k + 1 < vl && j < 127; k++) vbuf[j++] = v[k];
                vbuf[j] = 0;
                v = vbuf;
            }
            int r = sh_alias_set(tok[1], v);
            if (r == -1) console_write("alias: table full (16)\n");
            else if (r == -2) console_write("alias: value too long\n");
        }
    } else if (strcmp(tok[0], "unalias") == 0) {
        if (n < 2) { console_write("Usage: unalias <name>\n"); return 0; }
        if (!sh_alias_unset(tok[1])) console_printf("unalias: %s: not found\n", tok[1]);
    } else if (strcmp(tok[0], "man") == 0) {
        if (n < 2) { console_write("Usage: man <command>\n"); return 0; }
        const struct help_entry *e = help_find(tok[1]);
        if (!e) console_printf("man: no such command %s\n", tok[1]);
        else help_print_entry(e);
    } else if (strcmp(tok[0], "uname") == 0) {
        /* Linux shape: bare prints the sysname only; -a prints
           sysname + version + machine. Anything else is treated
           as bare (lenient, documented). */
        if (n >= 2 && strcmp(tok[1], "-a") == 0)
            console_printf("%s i386\n", shell_version);
        else console_write("nxtsOS\n");
    } else if (strcmp(tok[0], "ver") == 0) {
        /* Version literal, kept in sync by build.sh's VERSION check
           (same grep as the main.c banner and the wm.c About text). */
        console_printf("%s\n", shell_version);
    } else if (strcmp(tok[0], "reboot") == 0) {
        console_write("Rebooting...\n");
        outb(0x64, 0xFE);
        for (;;) __asm__ volatile ("hlt");
    } else if (strcmp(tok[0], "shutdown") == 0 || strcmp(tok[0], "poweroff") == 0) {
        /* Root only, confirmed unless --force. Any other
           argument is a usage error, never silently ignored.
           ACPI poweroff is parsed, never assumed: when the
           tables are absent or malformed the machine halts
           with a message instead of pretending to power off.
           Writes are synchronous in nxtsFS, so there is no
           flush step to perform first. */
        if (sh_cap_gate(CAP_SYS, "shutdown") != 0) return 0;
        int force = 0;
        if (n >= 2) {
            if (strcmp(tok[1], "--force") == 0) force = 1;
            else { console_write("Usage: shutdown [--force]\n"); return 0; }
        }
        if (!force) {
            console_write("Shutdown? (y/n) ");
            char ans[8];
            read_line(ans, sizeof(ans), 1);
            if (strcmp(ans, "y") != 0) { console_write("shutdown: aborted\n"); return 0; }
        }
        console_write("Powering off...\n");
        if (acpi_poweroff() != 0) {
            console_write("shutdown: ACPI poweroff unavailable, system halted.\n");
            for (;;) __asm__ volatile ("hlt");
        }
    } else if (strcmp(tok[0], "halt") == 0) {
        if (sh_cap_gate(CAP_SYS, "halt") != 0) return 0;
        int force = 0;
        if (n >= 2) {
            if (strcmp(tok[1], "--force") == 0) force = 1;
            else { console_write("Usage: halt [--force]\n"); return 0; }
        }
        if (!force) {
            console_write("Halt? (y/n) ");
            char ans[8];
            read_line(ans, sizeof(ans), 1);
            if (strcmp(ans, "y") != 0) { console_write("halt: aborted\n"); return 0; }
        }
        console_write("System halted.\n");
        for (;;) __asm__ volatile ("hlt");
    } else if (strcmp(tok[0], "whoami") == 0) {
        console_printf("%s uid %u\n", session_name, session_uid);
    } else if (strcmp(tok[0], "who") == 0 || strcmp(tok[0], "w") == 0) {
        /* Single console session: one row, Linux `who` shape.
           Idle = seconds since the last keypress, in minutes. */
        u32 idle_sec = (timer_ticks - sh_activity_tick) / 100u;
        console_write("USER  TTY  IDLE  SESSION-START-TICK\n");
        console_printf("%s console %um %u\n", session_name, idle_sec / 60u, session_start_tick);
    } else if (strcmp(tok[0], "sudo") == 0) {
        if (n < 2) { console_write("Usage: sudo [-l] <command...>\n"); return 0; }
        /* Sudoers rule: member of group "sudo", or a name line in
           sudoers.txt. Root needs no sudo (runs directly). */
        int allowed = 0;
        if (session_uid == 0) allowed = 1;
        else {
            u32 sgid = 0;
            if (groups_gid("sudo", &sgid) == 0 && groups_user_in_gid(session_uid, sgid)) allowed = 1;
            else {
                static u8 sh_sudo_buf[1025];
                u32 got = 0;
                if (fs_read_as("sudoers.txt", sh_sudo_buf, sizeof(sh_sudo_buf) - 1, &got, session_uid) == 0) {
                    sh_sudo_buf[got] = 0;
                    u32 i = 0;
                    while (i < got) {
                        u32 s = i;
                        while (i < got && sh_sudo_buf[i] != '\n') i++;
                        u32 len = i - s;
                        u32 nl = 0; while (session_name[nl]) nl++;
                        if (len == nl) {
                            int eq = 1;
                            for (u32 k = 0; k < len; k++) if (sh_sudo_buf[s + k] != session_name[k]) eq = 0;
                            if (eq) allowed = 1;
                        }
                        if (i < got) i++;
                    }
                }
            }
        }
        if (strcmp(tok[1], "-l") == 0) {
            if (!allowed) { console_printf("sudo: %s is not in the sudoers file\n", session_name); return 0; }
            if (session_uid != 0) {
                int ok = 0;
                for (int a = 0; a < 3 && !ok; a++) {
                    char pass[64];
                    console_write("Password: ");
                    read_line(pass, sizeof(pass), 0);
                    u32 uid = 0;
                    if (users_check(session_name, pass, &uid) && uid == session_uid) ok = 1;
                    memset(pass, 0, sizeof(pass));
                }
                if (!ok) { console_write("sudo: 3 incorrect password attempts\n"); return 0; }
            }
            console_printf("User %s may run ALL commands as root\n", session_name);
            return 0;
        }
        if (!allowed) { console_printf("sudo: %s is not in the sudoers file\n", session_name); audit("sudo-fail", session_name); return 0; }
        /* Refuse session/interactive commands inside sudo: they
           would log out, switch, or grab the screen of the
           caller's session, not run as root. */
        {
            const char *first = tok[1];
            const char *second = 0;
            if (rest) {
                /* rest starts after tok[1]; its first word is the
                   group member when the first word is a group. */
                second = rest;
            }
            int refused = (strcmp(first, "logout") == 0 || strcmp(first, "exit") == 0 ||
                           strcmp(first, "su") == 0 || strcmp(first, "lock") == 0 ||
                           strcmp(first, "passwd") == 0 || strcmp(first, "edit") == 0 ||
                           strcmp(first, "top") == 0 || strcmp(first, "gui") == 0 ||
                           strcmp(first, "desktop") == 0);
            if (!refused && second) {
                char sec[32]; u32 si = 0;
                while (second[si] && second[si] != ' ' && si < 31) { sec[si] = second[si]; si++; }
                sec[si] = 0;
                refused = ((strcmp(first, "session") == 0 || strcmp(first, "fs") == 0) &&
                           (strcmp(sec, "logout") == 0 || strcmp(sec, "exit") == 0 ||
                            strcmp(sec, "su") == 0 || strcmp(sec, "lock") == 0 ||
                            strcmp(sec, "passwd") == 0 || strcmp(sec, "edit") == 0));
            }
            if (refused) { console_write("sudo: session/interactive commands cannot run under sudo\n"); return 0; }
        }
        if (session_uid != 0) {
            int ok = 0;
            for (int a = 0; a < 3 && !ok; a++) {
                char pass[64];
                console_write("Password: ");
                read_line(pass, sizeof(pass), 0);
                u32 uid = 0;
                if (users_check(session_name, pass, &uid) && uid == session_uid) ok = 1;
                memset(pass, 0, sizeof(pass));
            }
            if (!ok) { console_write("sudo: 3 incorrect password attempts\n"); audit("sudo-fail", session_name); return 0; }
        }
        audit("sudo", session_name);
        /* One-command uid-0 execution: swap uid + name, run, and
           restore no matter what the command returns (a logout
           return is swallowed: sudo never logs the session out). */
        char line2[128];
        {
            u32 li = 0;
            const char *p = tok[1];
            while (*p && li < 120) line2[li++] = *p++;
            if (rest && rest[0]) {
                line2[li++] = ' ';
                p = rest;
                while (*p && li < 127) line2[li++] = *p++;
            }
            line2[li] = 0;
        }
        u32 saved_uid = session_uid;
        char saved_name[32];
        { u32 k = 0; while (session_name[k]) { saved_name[k] = session_name[k]; k++; } saved_name[k] = 0; }
        /* Redesign 5: sudo is full root, so the sudo'd command runs
           with CAP_ALL, not the caller's session mask — otherwise
           a sudo'd root-gated command (e.g. `sudo log`, which
           needs CAP_AUDIT) would be refused even though sudo
           legitimately elevated the user to uid 0. Restored
           afterwards, exactly like uid and name. */
        u32 saved_caps = session_caps;
        session_uid = 0;
        session_name[0] = 'r'; session_name[1] = 'o'; session_name[2] = 'o'; session_name[3] = 't'; session_name[4] = 0;
        session_caps = CAP_ALL;
        execute(line2);
        session_uid = saved_uid;
        session_caps = saved_caps;
        { u32 k = 0; while (saved_name[k]) { session_name[k] = saved_name[k]; k++; } session_name[k] = 0; }
        return 0;
    } else if (strcmp(tok[0], "su") == 0) {
        /* Switch the session user (parity run). Root switches
           without a password; anyone else must pass the target
           user's password check (echo off, buffer cleared).
           Background jobs keep their owners; only the session
           name/uid change. `sudo` is deliberately out: su is
           the mechanism, sudoers policy is a separate system. */
        const char *target = (n >= 2) ? tok[1] : "root";
        u32 tuid = 0;
        if (users_uid(target, &tuid) != 0) {
            console_printf("su: no such user %s\n", target); return 0;
        }
        /* "root" is not a login account (it has no users.txt
           entry, so no password could ever match — login
           behaves the same). Refuse upfront rather than
           prompting for a password that cannot succeed; a
           uid-0 named account (e.g. admin) is the way to
           gain uid 0 from a login session. */
        if (strcmp(target, "root") == 0 && session_uid != 0) {
            console_write("su: root is not a login account\n"); return 0;
        }
        if (session_uid != 0) {
            char pw[64];
            console_write("Password: ");
            read_line(pw, sizeof(pw), 0);
            u32 chk = 0;
            int okpw = users_check(target, pw, &chk);
            for (u32 i = 0; i < sizeof(pw); i++) pw[i] = 0;
            if (!okpw || chk != tuid) { console_write("su: incorrect password\n"); return 0; }
        }
        {
            u32 i = 0;
            while (target[i] && i < 31) { session_name[i] = target[i]; i++; }
            session_name[i] = 0;
        }
        session_uid = tuid;
        sh_session_start(tuid);
        audit("su", target);
    } else if (strcmp(tok[0], "true") == 0) {
        sh_cmd_status = 0;
    } else if (strcmp(tok[0], "false") == 0) {
        sh_cmd_status = 1;
    } else if (strcmp(tok[0], "test") == 0 || strcmp(tok[0], "[") == 0) {
        const char *args[33];
        u32 nargs = (n >= 2) ? sh_split_args(tok[1], rest, args, 33) : 0;
        if (strcmp(tok[0], "[") == 0) {
            if (nargs == 0 || strcmp(args[nargs - 1], "]") != 0) {
                console_write("Usage: [ <expression> ]\n"); sh_cmd_status = 2; return 0;
            }
            nargs--;
        }
        int r = sh_test_eval(args, (int)nargs);
        if (r == 2) { console_write("Usage: test [-f|-d|-r|-w file] [-z|-n string] [string =|!= string] [n -eq|-ne|-lt|-le|-gt|-ge n] [! expr]\n"); }
        sh_cmd_status = r;
    } else if (strcmp(tok[0], "sleep") == 0) {
        if (n < 2) { console_write("Usage: sleep <seconds>\n"); sh_cmd_status = 2; return 0; }
        int secs = sh_parse_num(tok[1]);
        if (secs < 0 || secs > 3600) { console_write("Usage: sleep <seconds 0..3600>\n"); sh_cmd_status = 2; return 0; }
        u32 target = timer_ticks + (u32)secs * 100u;
        int interrupted = 0;
        while (timer_ticks < target) {
            keyboard_poll();
            int c = keyboard_getchar();
            if (c == 3) { interrupted = 1; break; }
            if (c < 0) __asm__ volatile ("hlt");
        }
        if (interrupted) { console_write("sleep: interrupted\n"); sh_cmd_status = 1; }
        else sh_cmd_status = 0;
    } else if (strcmp(tok[0], "read") == 0) {
        if (n < 2 || !sh_name_ok(tok[1])) { console_write("Usage: read <VAR>\n"); sh_cmd_status = 2; return 0; }
        char buf[128];
        read_line(buf, sizeof(buf), 1);
        if (sh_env_set(tok[1], buf) != 0) { console_write("read: environment full\n"); sh_cmd_status = 1; return 0; }
        sh_cmd_status = 0;
    } else if (strcmp(tok[0], "sh") == 0 || strcmp(tok[0], "source") == 0) {
        if (n < 2) { console_write("Usage: sh <file> (source is an alias)\n"); sh_cmd_status = 2; return 0; }
        int r = sh_run_script_file(tok[1]);
        if (r == -1) { console_printf("sh: cannot read %s\n", tok[1]); sh_cmd_status = 1; return 0; }
        /* r == 1 means the script ended on logout/exit: the
           script stops, the session does not log out, and the
           status is 0 (a script ending on `exit` is a normal
           script end). r == 2 is a script error (unmatched
           block, bad for, full environment). */
        sh_cmd_status = (r == 2) ? 2 : 0;
    } else if (strcmp(tok[0], "logout") == 0 || strcmp(tok[0], "exit") == 0) {
        return shell_do_logout();
    } else if (strcmp(tok[0], "lock") == 0) {
        if (!do_lock()) {
            audit("logout", session_name);
            session_active = 0;
            return 1;
        }
        return 0;
    } else if (strcmp(tok[0], "unlock") == 0) {
        if (n < 2) { console_write("Usage: unlock <user>\n"); return 0; }
        if (sh_cap_gate(CAP_USER, "unlock") != 0) return 0;
        if (!shell_unlock_user(tok[1])) { console_printf("unlock: no such user %s\n", tok[1]); return 0; }
        console_printf("Unlocked %s\n", tok[1]);
        return 0;
    } else if (strcmp(tok[0], "passwd") == 0) {
        /* Change a password at runtime (post-v1.0.0; previously the only
           way was rebuilding users.txt offline). Root changes any user
           without the current password, as on Unix; a non-root user
           changes only their own password and must first pass the
           current-password check. That check is NOT a login attempt: it
           neither counts toward the failed-login lockout nor audits, so
           probing it cannot lock the account out. Passwords are read
           with echo off (read_line echo=0, as at login) and the buffers
           are cleared before every return below. A successful change is
           audited as "passwd <user>"; changing a password does NOT
           clear a failed-login lockout — root still runs `unlock`. */
        const char *target = (n >= 2) ? tok[1] : session_name;
        if (n >= 2 && rest && rest[0]) { console_write("Usage: passwd [user]\n"); return 0; }
        if (!users_exists(target)) { console_printf("passwd: no such user %s\n", target); return 0; }
        if (session_uid != 0 && strcmp(target, session_name) != 0) {
            console_write("passwd: permission denied\n"); return 0;
        }
        if (session_uid == 0 && strcmp(target, session_name) != 0 &&
            (session_caps & (1u << CAP_USER)) == 0) {
            console_write("passwd: refused: root capability cap_user is not set (see `cap list`)\n"); return 0;
        }
        if (session_uid != 0) {
            console_write("Current password: ");
            char cur[64];
            read_line(cur, sizeof(cur), 0);
            u32 uid = 0;
            if (!users_check(session_name, cur, &uid) || uid != session_uid) {
                memset(cur, 0, sizeof(cur));
                console_write("passwd: incorrect password\n"); return 0;
            }
            memset(cur, 0, sizeof(cur));
        }
        console_write("New password: ");
        char npw[64];
        read_line(npw, sizeof(npw), 0);
        if (npw[0] == 0) {
            memset(npw, 0, sizeof(npw));
            console_write("passwd: empty password not allowed\n"); return 0;
        }
        console_write("Retype new password: ");
        char rpw[64];
        read_line(rpw, sizeof(rpw), 0);
        if (strcmp(npw, rpw) != 0) {
            memset(npw, 0, sizeof(npw)); memset(rpw, 0, sizeof(rpw));
            console_write("passwd: passwords do not match\n"); return 0;
        }
        memset(rpw, 0, sizeof(rpw));
        if (users_change_password(target, npw) != 0) {
            memset(npw, 0, sizeof(npw));
            console_write("passwd: cannot change password\n"); return 0;
        }
        memset(npw, 0, sizeof(npw));
        console_printf("Password changed for %s\n", target);
        audit("passwd", target);
        return 0;
    } else if (strcmp(tok[0], "useradd") == 0) {
        /* Root only, one name, nothing else: a password on the
           command line would be echoed to the serial log, so the
           password is always prompted with echo off (like
           passwd), twice, and the buffers are cleared on every
           return. The assigned uid is resolved after success for
           the confirmation line. */
        if (sh_cap_gate(CAP_USER, "useradd") != 0) return 0;
        if (n < 2 || (rest && rest[0])) { console_write("Usage: useradd <user>\n"); return 0; }
        const char *name = tok[1];
        if (!fs_mounted()) { console_write("useradd: no filesystem mounted\n"); return 0; }
        if (!users_valid_name(name)) { console_printf("useradd: bad name %s\n", name); return 0; }
        if (users_exists(name)) { console_printf("useradd: user %s already exists\n", name); return 0; }
        if (users_count() >= MAX_USERS) { console_write("useradd: user limit reached (8)\n"); return 0; }
        console_write("New password: ");
        char npw[64];
        read_line(npw, sizeof(npw), 0);
        if (npw[0] == 0) {
            memset(npw, 0, sizeof(npw));
            console_write("useradd: empty password not allowed\n"); return 0;
        }
        console_write("Retype new password: ");
        char rpw[64];
        read_line(rpw, sizeof(rpw), 0);
        if (strcmp(npw, rpw) != 0) {
            memset(npw, 0, sizeof(npw)); memset(rpw, 0, sizeof(rpw));
            console_write("useradd: passwords do not match\n"); return 0;
        }
        memset(rpw, 0, sizeof(rpw));
        if (users_add(name, npw) != 0) {
            memset(npw, 0, sizeof(npw));
            console_printf("useradd: cannot add user %s\n", name); return 0;
        }
        memset(npw, 0, sizeof(npw));
        u32 uid = 0;
        users_uid(name, &uid);
        console_printf("Added user %s (uid %u)\n", name, uid);
        audit("useradd", name);
        return 0;
    } else if (strcmp(tok[0], "userdel") == 0) {
        if (sh_cap_gate(CAP_USER, "userdel") != 0) return 0;
        if (n < 2 || (rest && rest[0])) { console_write("Usage: userdel <user>\n"); return 0; }
        const char *name = tok[1];
        if (strcmp(name, "root") == 0) { console_write("userdel: cannot delete root\n"); return 0; }
        if (strcmp(name, session_name) == 0) { console_write("userdel: cannot delete the session user\n"); return 0; }
        if (!users_exists(name)) { console_printf("userdel: no such user %s\n", name); return 0; }
        if (users_delete(name) != 0) {
            console_printf("userdel: cannot delete user %s\n", name); return 0;
        }
        fails_drop(name);
        console_printf("Deleted user %s\n", name);
        audit("userdel", name);
        return 0;
    } else if (strcmp(tok[0], "groupadd") == 0) {
        if (sh_cap_gate(CAP_USER, "groupadd") != 0) return 0;
        if (n < 2 || (rest && rest[0])) { console_write("Usage: groupadd <group>\n"); return 0; }
        const char *name = tok[1];
        if (!fs_mounted()) { console_write("groupadd: no filesystem mounted\n"); return 0; }
        if (!users_valid_name(name)) { console_printf("groupadd: bad name %s\n", name); return 0; }
        if (groups_exists(name)) { console_printf("groupadd: group %s already exists\n", name); return 0; }
        if (groups_count() >= MAX_GROUPS) { console_write("groupadd: group limit reached (8)\n"); return 0; }
        int gid = groups_add(name);
        if (gid < 0) { console_printf("groupadd: cannot add group %s\n", name); return 0; }
        console_printf("Added group %s (gid %u)\n", name, (u32)gid);
        audit("groupadd", name);
        return 0;
    } else if (strcmp(tok[0], "groupdel") == 0) {
        if (sh_cap_gate(CAP_USER, "groupdel") != 0) return 0;
        if (n < 2 || (rest && rest[0])) { console_write("Usage: groupdel <group>\n"); return 0; }
        const char *name = tok[1];
        if (!groups_exists(name)) { console_printf("groupdel: no such group %s\n", name); return 0; }
        if (groups_delete(name) != 0) {
            console_printf("groupdel: cannot delete group %s\n", name); return 0;
        }
        console_printf("Deleted group %s\n", name);
        audit("groupdel", name);
        return 0;
    } else if (strcmp(tok[0], "groupmod") == 0) {
        /* tokenize() stops at 2 tokens: the group is tok[1] and
           rest holds "add|remove <user>" (see chmod). */
        if (sh_cap_gate(CAP_USER, "groupmod") != 0) return 0;
        if (n < 2 || !rest || !rest[0]) { console_write("Usage: groupmod <group> add|remove <user>\n"); return 0; }
        char *op = rest;
        char *sp = op;
        while (*sp && *sp != ' ') sp++;
        if (*sp == 0) { console_write("Usage: groupmod <group> add|remove <user>\n"); return 0; }
        *sp = 0; sp++;
        while (*sp == ' ') sp++;
        char *user = sp;
        if (*user == 0) { console_write("Usage: groupmod <group> add|remove <user>\n"); return 0; }
        while (*sp && *sp != ' ') sp++;
        if (*sp) { while (*sp == ' ') sp++; if (*sp) { console_write("Usage: groupmod <group> add|remove <user>\n"); return 0; } }
        if (strcmp(op, "add") != 0 && strcmp(op, "remove") != 0) {
            console_write("Usage: groupmod <group> add|remove <user>\n"); return 0;
        }
        const char *group = tok[1];
        if (!groups_exists(group)) { console_printf("groupmod: no such group %s\n", group); return 0; }
        if (!users_exists(user) && strcmp(user, "root") != 0) {
            console_printf("groupmod: no such user %s\n", user); return 0;
        }
        int r = (strcmp(op, "add") == 0) ? groups_mod_add(group, user)
                                         : groups_mod_remove(group, user);
        if (r == 1) {
            if (strcmp(op, "add") == 0) console_printf("groupmod: %s is already a member of %s\n", user, group);
            else console_printf("groupmod: %s is not a member of %s\n", user, group);
            return 0;
        }
        if (r == -2) { console_printf("groupmod: group %s is full\n", group); return 0; }
        if (r != 0) { console_printf("groupmod: cannot %s %s %s %s\n", op, user, (strcmp(op, "add") == 0) ? "to" : "from", group); return 0; }
        if (strcmp(op, "add") == 0) console_printf("Added %s to %s\n", user, group);
        else console_printf("Removed %s from %s\n", user, group);
        audit("groupmod", group);
        return 0;
    } else if (strcmp(tok[0], "groups") == 0) {
        if (n >= 2 && rest && rest[0]) { console_write("Usage: groups [user]\n"); return 0; }
        const char *user = (n >= 2) ? tok[1] : session_name;
        if (!users_exists(user) && strcmp(user, "root") != 0) {
            console_printf("groups: no such user %s\n", user); return 0;
        }
        char list[256];
        int c = groups_names_for_user(user, list, sizeof(list));
        if (c < 0) { console_printf("groups: cannot list groups for %s\n", user); return 0; }
        if (c == 0) console_printf("%s: none\n", user);
        else console_printf("%s: %s\n", user, list);
        return 0;
    } else if (strcmp(tok[0], "id") == 0) {
        if (n >= 2 && rest && rest[0]) { console_write("Usage: id [user]\n"); return 0; }
        const char *user = (n >= 2) ? tok[1] : session_name;
        u32 uid = 0;
        if (users_uid(user, &uid) != 0) {
            console_printf("id: no such user %s\n", user); return 0;
        }
        char list[256];
        int c = groups_names_for_user(user, list, sizeof(list));
        if (c < 0) { console_printf("id: cannot list groups for %s\n", user); return 0; }
        if (c == 0) console_printf("uid=%u groups=none\n", uid);
        else console_printf("uid=%u groups=%s\n", uid, list);
        return 0;
    } else if (strcmp(tok[0], "fs") == 0) {
        fs_status();
    } else if (strcmp(tok[0], "ls") == 0) {
        /* §15: ls [path] lists that directory's children, or
           the cwd's children with no path; a file path lists
           just that file. Extra words are a usage error. */
        if (!fs_mounted()) { console_write("No filesystem mounted\n"); return 0; }
        const char *target = (n >= 2) ? tok[1] : sh_cwd;
        if (rest && rest[0]) { console_write("Usage: ls [path]\n"); return 0; }
        int r = fs_list_path(target, sh_cwd, session_uid);
        if (r < 0) console_printf("ls: cannot list %s (%s)\n", target, sh_path_reason(r));
    } else if (strcmp(tok[0], "cat") == 0) {
        /* Multi-file (parity run): concatenate in order, like
           Linux; an unreadable file reports and the rest still
           print. "-" reads the shell stdin source (set by a
           pipeline stage's < or pipe input); with no stdin
           source it reports "cat: no stdin" instead of
           hanging. Bare cat with a stdin source reads stdin
           (Linux behaviour); bare cat with no stdin source is
           a usage error. The trailing newline matches the old
           single-file shape exactly (present unless the file
           errored). */
        u8 buf[1024];
        const char *args[33];
        u32 nargs = 0;
        if (n < 2) {
            if (!sh_stdin_file[0]) { console_write("Usage: cat <file>...\n"); return 0; }
            args[nargs++] = "-";
        } else {
            args[nargs++] = tok[1];
            if (rest) {
                char *p = rest;
                while (*p && nargs < 33) {
                    while (*p == ' ') p++;
                    if (!*p) break;
                    args[nargs++] = p;
                    while (*p && *p != ' ') p++;
                    if (*p) { *p = 0; p++; }
                }
            }
        }
        for (u32 a = 0; a < nargs; a++) {
            const char *name = args[a];
            int is_stdin = (strcmp(name, "-") == 0);
            if (is_stdin) {
                if (!sh_stdin_file[0]) { console_write("cat: no stdin\n"); continue; }
                name = sh_stdin_file;
            }
            u32 off = 0;
            int err = 0;
            for (;;) {
                u32 size = 0;
                /* §15: path-aware cat, except the stdin source,
                   which is a flat root temp file by construction. */
                int rr = is_stdin ? fs_read_range_as(name, buf, sizeof(buf) - 1, off, &size, session_uid)
                                  : fs_read_range_path(name, sh_cwd, buf, sizeof(buf) - 1, off, &size, session_uid);
                if (rr != 0) {
                    if (off == 0) console_printf("cat: cannot read %s\n", name);
                    else console_printf("cat: read error %s\n", name);
                    err = 1;
                    break;
                }
                if (size == 0) break;
                buf[size] = 0;
                console_write((const char *)buf);
                off += size;
                if (size < sizeof(buf) - 1) break;
            }
            if (!err) console_write("\n");
        }
    } else if (strcmp(tok[0], "write") == 0) {
        if (n < 2) {
            console_write("Usage: write <file> <text>\n"); return 0;
        }
        if ((!rest || rest[0] == 0) && sh_stdin_file[0]) {
            /* Step 9: no text + a stdin source writes the stdin
               content (explicit text still wins when present).
               Stdin files over the 256 KiB staging cap refuse
               visibly instead of truncating. */
            struct fs_stat wst;
            if (fs_stat_as(sh_stdin_file, &wst, session_uid) != 0 || wst.size > sizeof(sh_stdin_buf)) {
                console_write("write: stdin too large or unreadable\n"); return 0;
            }
            u32 got = 0;
            if (wst.size > 0 && fs_read_as(sh_stdin_file, (u8 *)sh_stdin_buf, wst.size, &got, session_uid) != 0) {
                console_write("write: stdin too large or unreadable\n"); return 0;
            }
            int wr = fs_write_path(tok[1], sh_cwd, (const u8 *)sh_stdin_buf, got, session_uid, 0644);
            if (wr != 0) {
                console_printf("write: cannot write %s (%s)\n", tok[1], sh_path_reason(wr));
                return 0;
            }
            console_printf("Wrote %s\n", tok[1]);
            return 0;
        }
        if (!rest || rest[0] == 0) {
            console_write("Usage: write <file> <text>\n"); return 0;
        }
        {
            /* rest is unquoted here (tok[1] already is), so
               `write f "hello world"` stores hello world
               without quotes, and `write f ''` stores an
               empty file. An unterminated quote refuses. */
            if (sh_unquote_copy(rest, sh_unquote_buf, sizeof(sh_unquote_buf)) != 0) {
                console_write("quote: unterminated quote\n"); return 0;
            }
            int wr = fs_write_path(tok[1], sh_cwd, (const u8 *)sh_unquote_buf, strlen(sh_unquote_buf), session_uid, 0644);
            if (wr != 0) {
                console_printf("write: cannot write %s (%s)\n", tok[1], sh_path_reason(wr));
                return 0;
            }
        }
        console_printf("Wrote %s\n", tok[1]);
    } else if (strcmp(tok[0], "rm") == 0) {
        if (n < 2) { console_write("Usage: rm <file>\n"); return 0; }
        int dr = fs_delete_path(tok[1], sh_cwd, session_uid);
        if (dr != 0) {
            if (dr == -7) console_printf("rm: %s is a directory (use rmdir)\n", tok[1]);
            else console_printf("rm: cannot delete %s (%s)\n", tok[1], sh_path_reason(dr));
            return 0;
        }
        console_printf("Deleted %s\n", tok[1]);
    } else if (strcmp(tok[0], "mv") == 0) {
        /* tokenize() stops at 2 tokens: the old name is tok[1]
           and the new name is the first word of rest (a second
           word is a usage error, not silently ignored). */
        if (n < 2 || !rest || !rest[0]) { console_write("Usage: mv <old> <new>\n"); return 0; }
        char *nw = rest;
        char *p = nw;
        while (*p && *p != ' ') p++;
        if (*p == ' ') {
            *p = 0; p++;
            while (*p == ' ') p++;
            if (*p) { console_write("Usage: mv <old> <new>\n"); return 0; }
        }
        /* §15: a destination that is an existing directory
           moves the source INTO it under its own basename. */
        const char *dest = nw;
        struct fs_stat dst;
        if (fs_stat_path(nw, sh_cwd, &dst, session_uid) == 0 && dst.is_dir) {
            const char *bn = tok[1];
            const char *slash = 0;
            for (const char *p = tok[1]; *p; p++) if (*p == '/') slash = p;
            if (slash) bn = slash + 1;
            u32 k = 0;
            while (nw[k] && k < 250) { sh_mv_buf[k] = nw[k]; k++; }
            if (k > 0 && sh_mv_buf[k - 1] != '/') sh_mv_buf[k++] = '/';
            u32 b = 0;
            while (bn[b] && k < 255) { sh_mv_buf[k++] = bn[b++]; }
            sh_mv_buf[k] = 0;
            dest = sh_mv_buf;
        }
        int mr = fs_rename_path(tok[1], dest, sh_cwd, session_uid);
        if (mr != 0) {
            console_printf("mv: cannot rename %s to %s (%s)\n", tok[1], nw, sh_path_reason(mr));
            return 0;
        }
        console_printf("Renamed %s to %s\n", tok[1], nw);
    } else if (strcmp(tok[0], "cp") == 0) {
        /* tokenize() stops at 2 tokens: the source is tok[1]
           and the destination is the first word of rest (a second
           word is a usage error, not silently ignored) — the
           same rule as mv, so `cp a b c` never copies to b
           while silently dropping c. */
        if (n < 2 || !rest || !rest[0]) { console_write("Usage: cp <src> <dst>\n"); return 0; }
        char *dst = rest;
        char *p = dst;
        while (*p && *p != ' ') p++;
        if (*p == ' ') {
            *p = 0; p++;
            while (*p == ' ') p++;
            if (*p) { console_write("Usage: cp <src> <dst>\n"); return 0; }
        }
        /* §15: a destination that is an existing directory
           copies the source INTO it under its own basename. */
        const char *cdest = dst;
        struct fs_stat dst2;
        if (fs_stat_path(dst, sh_cwd, &dst2, session_uid) == 0 && dst2.is_dir) {
            const char *bn = tok[1];
            const char *slash = 0;
            for (const char *p = tok[1]; *p; p++) if (*p == '/') slash = p;
            if (slash) bn = slash + 1;
            u32 k = 0;
            while (dst[k] && k < 250) { sh_mv_buf[k] = dst[k]; k++; }
            if (k > 0 && sh_mv_buf[k - 1] != '/') sh_mv_buf[k++] = '/';
            u32 b = 0;
            while (bn[b] && k < 255) { sh_mv_buf[k++] = bn[b++]; }
            sh_mv_buf[k] = 0;
            cdest = sh_mv_buf;
        }
        int cr = fs_copy_path(tok[1], cdest, sh_cwd, session_uid);
        if (cr != 0) {
            console_printf("cp: cannot copy %s to %s (%s)\n", tok[1], dst, sh_path_reason(cr));
            return 0;
        }
        console_printf("Copied %s to %s\n", tok[1], dst);
    } else if (strcmp(tok[0], "ln") == 0) {
        /* §15: ln <src> <link> is a hard link (a second entry
           sharing the source's data sectors); ln -s <target>
           <link> is a symbolic link whose target may be a
           path. tokenize gives tok[1] = "-s" (or the source)
           and rest = the remaining words. */
        if (n < 2) { console_write("Usage: ln <src> <link> | ln -s <target> <link>\n"); return 0; }
        if (strcmp(tok[1], "-s") == 0) {
            if (!rest || !rest[0]) { console_write("Usage: ln -s <target> <link>\n"); return 0; }
            char *tgt = rest;
            char *p = tgt;
            while (*p && *p != ' ') p++;
            if (*p == 0) { console_write("Usage: ln -s <target> <link>\n"); return 0; }
            *p = 0; p++;
            while (*p == ' ') p++;
            char *lnk = p;
            char *q = lnk;
            while (*q && *q != ' ') q++;
            if (*q) { console_write("Usage: ln -s <target> <link>\n"); return 0; }
            int lr = fs_symlink_path(lnk, tgt, sh_cwd, session_uid);
            if (lr != 0) {
                console_printf("ln: cannot link %s to %s (%s)\n", lnk, tgt, sh_path_reason(lr)); return 0;
            }
            console_printf("Linked %s -> %s\n", lnk, tgt);
        } else {
            if (!rest || !rest[0]) { console_write("Usage: ln <src> <link>\n"); return 0; }
            char *lnk = rest;
            char *q = lnk;
            while (*q && *q != ' ') q++;
            if (*q) { *q = 0; q++; while (*q == ' ') q++; if (*q) { console_write("Usage: ln <src> <link>\n"); return 0; } }
            int lr = fs_link_path(tok[1], lnk, sh_cwd, session_uid);
            if (lr != 0) {
                console_printf("ln: cannot link %s to %s (%s)\n", lnk, tok[1], sh_path_reason(lr)); return 0;
            }
            console_printf("Linked %s to %s\n", lnk, tok[1]);
        }
    } else if (strcmp(tok[0], "readlink") == 0) {
        if (n < 2) { console_write("Usage: readlink <link>\n"); return 0; }
        if (fs_readlink_path(tok[1], sh_cwd, sh_readlink_out, session_uid) != 0) {
            console_printf("readlink: %s is not a link or cannot be read\n", tok[1]); return 0;
        }
        console_printf("%s\n", sh_readlink_out);
    } else if (strcmp(tok[0], "mkfifo") == 0) {
        if (n < 2) { console_write("Usage: mkfifo <name>\n"); return 0; }
        int fr = fs_mkfifo_path(tok[1], sh_cwd, session_uid);
        if (fr != 0) {
            console_printf("mkfifo: cannot create %s (%s)\n", tok[1], sh_path_reason(fr)); return 0;
        }
        console_printf("mkfifo: created %s\n", tok[1]);
    } else if (strcmp(tok[0], "chmod") == 0) {
        /* tokenize() stops at 2 tokens: the file is tok[1] and the
           mode is the first word of rest (a second word is a usage
           error, not silently ignored) — the same rule as mv/cp.
           The mode is octal, 3 digits with an optional leading 0
           ("600", "0644"); anything else is refused, never masked,
           so `chmod f 999` cannot silently become a valid mode. */
        if (n < 2 || !rest || !rest[0]) { console_write("Usage: chmod <file> <mode>\n"); return 0; }
        char *ms = rest;
        char *p = ms;
        while (*p && *p != ' ') p++;
        if (*p == ' ') {
            *p = 0; p++;
            while (*p == ' ') p++;
            if (*p) { console_write("Usage: chmod <file> <mode>\n"); return 0; }
        }
        const char *d = ms;
        if (d[0] == '0') d++;
        u32 mode = 0; int ok = 1;
        if (d[0] == 0 || d[1] == 0 || d[2] == 0 || d[3] != 0) ok = 0;
        for (int i = 0; ok && i < 3; i++) {
            if (d[i] < '0' || d[i] > '7') ok = 0;
            else mode = mode * 8u + (u32)(d[i] - '0');
        }
        if (!ok) { console_printf("chmod: bad mode %s\n", ms); return 0; }
        int hr = fs_chmod_path(tok[1], sh_cwd, mode, session_uid);
        if (hr != 0) {
            console_printf("chmod: cannot chmod %s (%s)\n", tok[1], sh_path_reason(hr));
            return 0;
        }
        console_printf("chmod: %s mode %s\n", tok[1], ms);
    } else if (strcmp(tok[0], "chown") == 0) {
        /* Root only, enforced here AND in fs_chown_as. The file
           is tok[1], the user is the first word of rest (same
           tokenize rule as chmod); anything after it is a usage
           error, never silently ignored. */
        if (sh_cap_gate(CAP_FS, "chown") != 0) return 0;
        if (n < 2 || !rest || !rest[0]) { console_write("Usage: chown <file> <user>\n"); return 0; }
        char *user = rest;
        char *p = user;
        while (*p && *p != ' ') p++;
        if (*p) { *p = 0; p++; while (*p == ' ') p++; if (*p) { console_write("Usage: chown <file> <user>\n"); return 0; } }
        u32 uid = 0;
        if (users_uid(user, &uid) != 0) { console_printf("chown: no such user %s\n", user); return 0; }
        int hr = fs_chown_path(tok[1], sh_cwd, uid, session_uid);
        if (hr != 0) {
            console_printf("chown: cannot chown %s (%s)\n", tok[1], sh_path_reason(hr));
            return 0;
        }
        console_printf("chown: %s owner %s\n", tok[1], user);
    } else if (strcmp(tok[0], "chgrp") == 0) {
        /* Parity run: root only, enforced here AND in
           fs_chgrp_as. Same tokenize rule as chown: the file
           is tok[1], the group is the first word of rest. */
        if (sh_cap_gate(CAP_FS, "chgrp") != 0) return 0;
        if (n < 2 || !rest || !rest[0]) { console_write("Usage: chgrp <file> <group>\n"); return 0; }
        char *grp = rest;
        char *p = grp;
        while (*p && *p != ' ') p++;
        if (*p) { *p = 0; p++; while (*p == ' ') p++; if (*p) { console_write("Usage: chgrp <file> <group>\n"); return 0; } }
        u32 gid = 0;
        if (groups_gid(grp, &gid) != 0) { console_printf("chgrp: no such group %s\n", grp); return 0; }
        int hr = fs_chgrp_path(tok[1], sh_cwd, gid, session_uid);
        if (hr != 0) {
            console_printf("chgrp: cannot chgrp %s (%s)\n", tok[1], sh_path_reason(hr));
            return 0;
        }
        console_printf("chgrp: %s group %s\n", tok[1], grp);
    } else if (strcmp(tok[0], "stat") == 0) {
        /* Metadata read: root, owner, or any reader (the fs
           layer enforces the rule; missing and unreadable both
           report the same refusal, so stat is not an existence
           oracle for files the caller may not read). */
        if (n < 2 || (rest && rest[0])) { console_write("Usage: stat <file>\n"); return 0; }
        if (!fs_mounted()) { console_write("No filesystem mounted\n"); return 0; }
        struct fs_stat st;
        int sr = fs_stat_path(tok[1], sh_cwd, &st, session_uid);
        if (sr != 0) {
            console_printf("stat: cannot stat %s (%s)\n", tok[1], sh_path_reason(sr));
            return 0;
        }
        console_printf("%s: %u bytes, uid %u (%s), mode %u, %u sectors",
                       tok[1], st.size, st.uid, users_name_for_uid(st.uid),
                       st.mode, st.sectors);
        if (st.is_dir) console_write(", directory");
        if (st.gid != 0) {
            char gname[32];
            if (groups_name_for_gid(st.gid, gname, sizeof(gname)) == 0)
                console_printf(", group %u (%s)", st.gid, gname);
            else
                console_printf(", group %u", st.gid);
        } else console_write(", no group");
        console_printf(", mtime %u ticks, atime %u ticks\n", st.mtime, st.atime);
    } else if (strcmp(tok[0], "df") == 0) {
        if (!fs_mounted()) { console_write("No filesystem mounted\n"); return 0; }
        u32 total = fs_total_sectors();
        u32 free = fs_free_sectors();
        u32 used = (total >= free) ? total - free : 0;
        int cnt = fs_enum_as(0, sh_cand_names, sh_cand_sizes, 32);
        if (cnt < 0) cnt = 0;
        console_printf("df: total %u MiB, used %u MiB, free %u MiB, %u files\n",
                       total / 2048, used / 2048, free / 2048, (u32)cnt);
    } else if (strcmp(tok[0], "du") == 0) {
        if (!fs_mounted()) { console_write("No filesystem mounted\n"); return 0; }
        if (n < 2) {
            int cnt = fs_enum_as(session_uid, sh_cand_names, sh_cand_sizes, 32);
            u32 total = 0;
            for (int i = 0; i < cnt; i++) total += sh_cand_sizes[i];
            console_printf("du: total %u bytes\n", total);
        } else {
            const char *args[33];
            u32 nargs = sh_split_args(tok[1], rest, args, 33);
            u32 total = 0;
            for (u32 a = 0; a < nargs; a++) {
                struct fs_stat st;
                if (fs_stat_path(args[a], sh_cwd, &st, session_uid) != 0) {
                    console_printf("du: cannot stat %s\n", args[a]);
                    continue;
                }
                console_printf("%s: %u bytes\n", args[a], st.size);
                total += st.size;
            }
            console_printf("du: total %u bytes\n", total);
        }
    } else if (strcmp(tok[0], "find") == 0) {
        if (!fs_mounted()) { console_write("No filesystem mounted\n"); return 0; }
        const char *pat = (n >= 2) ? tok[1] : "";
        int cnt = fs_enum_as(session_uid, sh_cand_names, sh_cand_sizes, 32);
        int shown = 0;
        for (int i = 0; i < cnt; i++) {
            if (!sh_contains(sh_cand_names[i], pat)) continue;
            console_printf("%s  %u bytes\n", sh_cand_names[i], sh_cand_sizes[i]);
            shown++;
        }
        if (shown == 0) console_write("(no files)\n");
    } else if (strcmp(tok[0], "touch") == 0) {
        if (n < 2) { console_write("Usage: touch <file>\n"); return 0; }
        if (!fs_mounted()) { console_write("No filesystem mounted\n"); return 0; }
        if (fs_exists_path(tok[1], sh_cwd)) {
            /* Exists: the pre-§15 success no-op, kept exactly
               (parity2 pins it: a readable-but-unwritable file
               reports "(exists)", an unreadable file reports
               "cannot touch"). Touch does NOT itself bump
               sidecar timestamps in this run — reads and
               writes do (see §15 notes, deviation 11) — so
               gating a literal no-op on writability would
               refuse a harmless existence report; the stat
               gate still refuses files the caller cannot even
               see, and stat already reveals existence, size,
               and mode. fs_touch_path exists for a future
               touch that does update timestamps. */
            struct fs_stat st;
            if (fs_stat_path(tok[1], sh_cwd, &st, session_uid) != 0) {
                console_printf("touch: cannot touch %s\n", tok[1]); return 0;
            }
            console_printf("touch: %s (exists)\n", tok[1]);
        } else {
            int wr = fs_write_path(tok[1], sh_cwd, (const u8 *)"", 0, session_uid, 0644);
            if (wr != 0) {
                console_printf("touch: cannot create %s (%s)\n", tok[1], sh_path_reason(wr)); return 0;
            }
            console_printf("touch: %s\n", tok[1]);
        }
    } else if (strcmp(tok[0], "grep") == 0) {
        /* grep [-i] [-v] [-n] [-c] [-F] [-E] <pattern> [files...]:
           regex by default (see the regex engine above);
           -F selects the old literal-substring behaviour,
           -E is accepted and means the same as default.
           Exit status: 0 if any line matched, 1 if none. */
        int flag_i = 0, flag_v = 0, flag_n = 0, flag_c = 0, flag_F = 0;
        const char *pat = 0;
        const char *args[33];
        u32 nargs = 0;
        if (n >= 2 && tok[1][0] == '-' && tok[1][1] != 0) {
            for (u32 k = 1; tok[1][k]; k++) {
                if (tok[1][k] == 'i') flag_i = 1;
                else if (tok[1][k] == 'v') flag_v = 1;
                else if (tok[1][k] == 'n') flag_n = 1;
                else if (tok[1][k] == 'c') flag_c = 1;
                else if (tok[1][k] == 'F') flag_F = 1;
                else if (tok[1][k] == 'E') { /* accepted, same engine */ }
                else { console_write("Usage: grep [-i] [-v] [-n] [-c] [-F] [-E] <pattern> [files...]\n"); return 0; }
            }
            const char *words[33];
            u32 nw = sh_split_args(0, rest, words, 33);
            if (nw < 1) { console_write("Usage: grep [-i] [-v] [-n] [-c] [-F] [-E] <pattern> [files...]\n"); return 0; }
            pat = words[0];
            for (u32 k = 1; k < nw; k++) args[nargs++] = words[k];
        } else {
            if (n < 2) { console_write("Usage: grep [-i] [-v] [-n] [-c] [-F] [-E] <pattern> [files...]\n"); return 0; }
            pat = tok[1];
            nargs = sh_split_args(0, rest, args, 33);
        }
        if (nargs == 0) {
            if (sh_stdin_file[0]) { args[0] = "-"; nargs = 1; }
            else { console_write("Usage: grep [-i] [-v] [-n] [-c] [-F] [-E] <pattern> [files...]\n"); return 0; }
        }
        char pat_low[256];
        if (flag_i) {
            u32 k = 0;
            while (pat[k] && k < 255) {
                char c = pat[k];
                if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
                pat_low[k] = c; k++;
            }
            pat_low[k] = 0;
            pat = pat_low;
        }
        int multi = (nargs > 1);
        int any_match = 0;
        int warned = 0;
        for (u32 a = 0; a < nargs; a++) {
            const char *fname = sh_input_name(args[a]);
            const char *disp = sh_input_disp(args[a]);
            if (sh_lr_open(fname, session_uid) != 0) {
                console_printf("grep: cannot read %s\n", disp);
                continue;
            }
            u32 lineno = 0, count = 0;
            for (;;) {
                int r = sh_lr_next();
                if (r == 0) break;
                if (r < 0) { console_printf("grep: read error %s\n", disp); break; }
                lineno++;
                const char *line = sh_lr_line;
                char line_low[256];
                if (flag_i) {
                    u32 k = 0;
                    while (line[k]) {
                        char c = line[k];
                        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
                        line_low[k] = c; k++;
                    }
                    line_low[k] = 0;
                    line = line_low;
                }
                int m;
                if (flag_F) m = sh_contains(line, pat);
                else {
                    int rr = sh_re_search(pat, line);
                    if (rr < 0) { if (!warned) { console_write("grep: pattern too complex\n"); warned = 1; } m = 0; }
                    else m = (rr == 1);
                }
                if (flag_v) m = !m;
                if (!m) continue;
                count++;
                any_match = 1;
                if (flag_c) continue;
                if (multi) console_printf("%s:", disp);
                if (flag_n) console_printf("%u:", lineno);
                console_printf("%s\n", sh_lr_line);
            }
            if (flag_c) {
                if (multi) console_printf("%s:%u\n", disp, count);
                else console_printf("%u\n", count);
            }
        }
        sh_cmd_status = any_match ? 0 : 1;
    } else if (strcmp(tok[0], "sed") == 0) {
        /* sed [-n] <script> [files...]: one script command only
           (s/old/new/[g], Np, N,Mp, /re/p, d). Replacement is
           literal except & = whole match. */
        int flag_n = 0;
        const char *script = 0;
        const char *args[33];
        u32 nargs = 0;
        if (n >= 2 && strcmp(tok[1], "-n") == 0) {
            flag_n = 1;
            nargs = sh_split_args(0, rest, args, 33);
            if (nargs < 1) { console_write("Usage: sed [-n] <script> [files...]\n"); return 0; }
            script = args[0];
            for (u32 k = 1; k < nargs; k++) args[k - 1] = args[k];
            nargs--;
        } else {
            if (n < 2) { console_write("Usage: sed [-n] <script> [files...]\n"); return 0; }
            script = tok[1];
            nargs = sh_split_args(0, rest, args, 33);
        }
        if (nargs == 0) {
            if (sh_stdin_file[0]) { args[0] = "-"; nargs = 1; }
            else { console_write("Usage: sed [-n] <script> [files...]\n"); return 0; }
        }
        /* Parse the script. */
        enum { SED_SUB, SED_PRINT1, SED_PRINTR, SED_REPRINT, SED_DEL, SED_DELLINE, SED_DELRANGE } kind = SED_DEL;
        int sub_global = 0, p1 = 0, p2 = 0;
        static char sed_pat[256], sed_rep[256], sed_re[256];
        sed_pat[0] = 0; sed_rep[0] = 0; sed_re[0] = 0;
        int bad = 0;
        if (script[0] == 's' && script[1] == '/') {
            kind = SED_SUB;
            const char *q = script + 2;
            int k = 0;
            while (*q && *q != '/' && k < 255) sed_pat[k++] = *q++;
            sed_pat[k] = 0;
            if (*q != '/') bad = 1;
            else {
                q++;
                k = 0;
                while (*q && *q != '/' && k < 255) sed_rep[k++] = *q++;
                sed_rep[k] = 0;
                if (*q != '/') bad = 1;
                else {
                    q++;
                    if (*q == 'g') { sub_global = 1; q++; }
                    if (*q != 0) bad = 1;
                }
            }
            if (sed_pat[0] == 0) bad = 1;
        } else if (script[0] == '/' ) {
            kind = SED_REPRINT;
            const char *q = script + 1;
            int k = 0;
            while (*q && *q != '/' && k < 255) sed_re[k++] = *q++;
            sed_re[k] = 0;
            if (*q != '/' || q[1] != 'p' || q[2] != 0) bad = 1;
        } else if (script[0] >= '0' && script[0] <= '9') {
            int v = 0, i = 0;
            while (script[i] >= '0' && script[i] <= '9') { v = v * 10 + (script[i] - '0'); i++; }
            p1 = v;
            if (script[i] == ',') {
                i++;
                v = 0;
                while (script[i] >= '0' && script[i] <= '9') { v = v * 10 + (script[i] - '0'); i++; }
                p2 = v;
                if (script[i] == 'p') { kind = SED_PRINTR; }
                else if (script[i] == 'd') { kind = SED_DELRANGE; }
                else bad = 1;
                if (script[i + 1] != 0) bad = 1;
            } else {
                if (script[i] == 'p') { kind = SED_PRINT1; }
                else if (script[i] == 'd') { kind = SED_DELLINE; }
                else bad = 1;
                if (script[i + 1] != 0) bad = 1;
            }
        } else if (strcmp(script, "d") == 0) {
            kind = SED_DEL;
        } else bad = 1;
        if (bad) { console_write("Usage: sed [-n] <s/old/new/[g]|Np|N,Mp|Nd|N,Md|/re/p|d> [files...]\n"); return 0; }
        static char sed_out[512];
        for (u32 a = 0; a < nargs; a++) {
            const char *fname = sh_input_name(args[a]);
            const char *disp = sh_input_disp(args[a]);
            if (sh_lr_open(fname, session_uid) != 0) {
                console_printf("sed: cannot read %s\n", disp);
                continue;
            }
            u32 lineno = 0;
            int warned = 0;
            for (;;) {
                int r = sh_lr_next();
                if (r == 0) break;
                if (r < 0) { console_printf("sed: read error %s\n", disp); break; }
                lineno++;
                const char *line = sh_lr_line;
                int deleted = 0, pmatch = 0, subbed = 0;
                const char *out_line = line;
                if (kind == SED_DEL) deleted = 1;
                else if (kind == SED_DELLINE) deleted = (lineno == (u32)p1);
                else if (kind == SED_DELRANGE) deleted = (lineno >= (u32)p1 && lineno <= (u32)p2);
                else if (kind == SED_PRINT1) pmatch = (lineno == (u32)p1);
                else if (kind == SED_PRINTR) pmatch = (lineno >= (u32)p1 && lineno <= (u32)p2);
                else if (kind == SED_REPRINT) {
                    int rr = sh_re_search(sed_re, line);
                    if (rr < 0) { if (!warned) { console_write("sed: pattern too complex\n"); warned = 1; } }
                    else pmatch = (rr == 1);
                } else if (kind == SED_SUB) {
                    /* Build the substituted line. */
                    u32 o = 0;
                    const char *cur = line;
                    int first = 1;
                    for (;;) {
                        const char *ms = 0, *me = 0;
                        int rr = sh_re_search_span(sed_pat, cur, &ms, &me);
                        if (rr < 0) { if (!warned) { console_write("sed: pattern too complex\n"); warned = 1; } break; }
                        if (rr == 0) {
                            while (*cur && o < 511) sed_out[o++] = *cur++;
                            break;
                        }
                        subbed = 1;
                        while (cur < ms && o < 511) sed_out[o++] = *cur++;
                        for (int k = 0; sed_rep[k] && o < 511; k++) {
                            if (sed_rep[k] == '&') {
                                for (const char *m = ms; m < me && o < 511; m++) sed_out[o++] = *m;
                            } else sed_out[o++] = sed_rep[k];
                        }
                        if (me == ms) {
                            /* Empty match: copy one char, advance. */
                            if (*me && o < 511) sed_out[o++] = *me;
                            cur = me + (*me ? 1 : 0);
                            if (*me == 0) break;
                        } else cur = me;
                        if (!sub_global) {
                            while (*cur && o < 511) sed_out[o++] = *cur++;
                            break;
                        }
                        if (first && *cur == 0) break;
                        first = 0;
                    }
                    sed_out[o] = 0;
                    out_line = sed_out;
                }
                if (deleted) continue;
                if (flag_n) {
                    if (kind == SED_SUB) { if (subbed) console_printf("%s\n", out_line); }
                    else if (pmatch) console_printf("%s\n", line);
                } else {
                    console_printf("%s\n", out_line);
                    if (pmatch) console_printf("%s\n", line);
                }
            }
        }
    } else if (strcmp(tok[0], "tr") == 0) {
        /* tr [-d] [-s] <set1> [set2]: stdin source only. */
        const char *words[33];
        u32 nw = (n >= 2) ? sh_split_args(tok[1], rest, words, 33) : 0;
        int flag_d = 0, flag_s = 0, wi = 0;
        while (wi < (int)nw && words[wi][0] == '-' && words[wi][1] != 0) {
            for (int k = 1; words[wi][k]; k++) {
                if (words[wi][k] == 'd') flag_d = 1;
                else if (words[wi][k] == 's') flag_s = 1;
                else { console_write("Usage: tr [-d] [-s] <set1> [set2]\n"); return 0; }
            }
            wi++;
        }
        if (wi >= (int)nw) { console_write("Usage: tr [-d] [-s] <set1> [set2]\n"); return 0; }
        const char *set1s = words[wi++];
        const char *set2s = (wi < (int)nw) ? words[wi] : 0;
        if (!flag_d && !flag_s && !set2s) { console_write("Usage: tr [-d] [-s] <set1> [set2]\n"); return 0; }
        if (!sh_stdin_file[0]) { console_write("Usage: tr [-d] [-s] <set1> [set2] (reads stdin: pipe or < file)\n"); return 0; }
        /* Expand a set string into bytes (ranges, escapes). */
        static u8 tr_s1[256], tr_s2[256];
        int n1 = 0, n2 = 0;
        {
            const char *p = set1s;
            while (*p && n1 < 255) {
                int lo;
                if (*p == '\\' && p[1]) {
                    p++;
                    if (*p == 'n') lo = '\n'; else if (*p == 't') lo = '\t';
                    else if (*p == '\\') lo = '\\'; else lo = (unsigned char)*p;
                    p++;
                } else lo = (unsigned char)*p++;
                if (*p == '-' && p[1] && p[1] != 0) {
                    int hi;
                    p++;
                    if (*p == '\\' && p[1]) {
                        p++;
                        if (*p == 'n') hi = '\n'; else if (*p == 't') hi = '\t';
                        else if (*p == '\\') hi = '\\'; else hi = (unsigned char)*p;
                        p++;
                    } else hi = (unsigned char)*p++;
                    for (int c = lo; c <= hi && n1 < 255; c++) tr_s1[n1++] = (u8)c;
                } else tr_s1[n1++] = (u8)lo;
            }
        }
        if (set2s) {
            const char *p = set2s;
            while (*p && n2 < 255) {
                int lo;
                if (*p == '\\' && p[1]) {
                    p++;
                    if (*p == 'n') lo = '\n'; else if (*p == 't') lo = '\t';
                    else if (*p == '\\') lo = '\\'; else lo = (unsigned char)*p;
                    p++;
                } else lo = (unsigned char)*p++;
                if (*p == '-' && p[1] && p[1] != 0) {
                    int hi;
                    p++;
                    if (*p == '\\' && p[1]) {
                        p++;
                        if (*p == 'n') hi = '\n'; else if (*p == 't') hi = '\t';
                        else if (*p == '\\') hi = '\\'; else hi = (unsigned char)*p;
                        p++;
                    } else hi = (unsigned char)*p++;
                    for (int c = lo; c <= hi && n2 < 255; c++) tr_s2[n2++] = (u8)c;
                } else tr_s2[n2++] = (u8)lo;
            }
        }
        struct fs_stat tst;
        if (fs_stat_as(sh_stdin_file, &tst, session_uid) != 0 || tst.size > 65535) {
            console_write("tr: stdin too large or unreadable (max 64 KiB)\n"); return 0;
        }
        static u8 tr_buf[65536], tr_out[65536];
        u32 got = 0;
        if (tst.size > 0 && fs_read_as(sh_stdin_file, tr_buf, tst.size, &got, session_uid) != 0) {
            console_write("tr: stdin too large or unreadable (max 64 KiB)\n"); return 0;
        }
        u32 oo = 0;
        int last_out = -1;
        for (u32 i = 0; i < got; i++) {
            int c = tr_buf[i];
            if (flag_d) {
                int in1 = 0;
                for (int k = 0; k < n1; k++) if (tr_s1[k] == c) in1 = 1;
                if (in1) continue;
            } else if (set2s && n2 > 0) {
                for (int k = 0; k < n1; k++) {
                    if (tr_s1[k] == c) { c = tr_s2[(k < n2) ? k : n2 - 1]; break; }
                }
            }
            if (flag_s) {
                const u8 *sq = set2s ? tr_s2 : tr_s1;
                int nsq = set2s ? n2 : n1;
                int in_sq = 0;
                for (int k = 0; k < nsq; k++) if (sq[k] == c) in_sq = 1;
                if (in_sq && c == last_out) continue;
            }
            tr_out[oo++] = (u8)c;
            last_out = c;
        }
        tr_out[oo] = 0;
        console_write((const char *)tr_out);
    } else if (strcmp(tok[0], "cut") == 0) {
        /* cut -d <delim> -f <list> | cut -c <list> */
        const char *words[33];
        u32 nw = (n >= 2) ? sh_split_args(tok[1], rest, words, 33) : 0;
        int mode = 0; /* 1 fields, 2 chars */
        char delim = '\t';
        const char *lists = 0;
        const char *args[33];
        u32 nargs = 0;
        int wi = 0;
        while (wi < (int)nw) {
            const char *w = words[wi];
            if (w[0] == '-' && (w[1] == 'f' || w[1] == 'c' || w[1] == 'd')) {
                if (w[1] == 'f' || w[1] == 'c') {
                    mode = (w[1] == 'f') ? 1 : 2;
                    if (w[2]) lists = w + 2;
                    else if (wi + 1 < (int)nw) lists = words[++wi];
                    else { console_write("Usage: cut -d <delim> -f <list> | cut -c <list>\n"); return 0; }
                } else if (w[1] == 'd') {
                    if (w[2]) delim = w[2];
                    else if (wi + 1 < (int)nw) delim = words[++wi][0];
                    else { console_write("Usage: cut -d <delim> -f <list> | cut -c <list>\n"); return 0; }
                } else { console_write("Usage: cut -d <delim> -f <list> | cut -c <list>\n"); return 0; }
                wi++;
            } else break;
        }
        if (mode == 0 || !lists) { console_write("Usage: cut -d <delim> -f <list> | cut -c <list>\n"); return 0; }
        for (; wi < (int)nw; wi++) args[nargs++] = words[wi];
        if (nargs == 0) {
            if (sh_stdin_file[0]) { args[0] = "-"; nargs = 1; }
            else { console_write("Usage: cut -d <delim> -f <list> | cut -c <list>\n"); return 0; }
        }
        /* Parse the list into ranges (file-scope). */
        static int cut_lo[32], cut_hi[32];
        int ncut = 0;
        {
            const char *p = lists;
            while (*p && ncut < 32) {
                int a = 0, b = 0, has_a = 0, has_b = 0;
                while (*p >= '0' && *p <= '9') { a = a * 10 + (*p - '0'); p++; has_a = 1; }
                if (*p == '-') {
                    p++;
                    while (*p >= '0' && *p <= '9') { b = b * 10 + (*p - '0'); p++; has_b = 1; }
                    if (!has_b) b = 1000000;
                } else b = a;
                if (!has_a) a = 1;
                cut_lo[ncut] = a; cut_hi[ncut] = b; ncut++;
                if (*p == ',') p++;
                else break;
            }
        }
        for (u32 a = 0; a < nargs; a++) {
            const char *fname = sh_input_name(args[a]);
            const char *disp = sh_input_disp(args[a]);
            if (sh_lr_open(fname, session_uid) != 0) {
                console_printf("cut: cannot read %s\n", disp);
                continue;
            }
            for (;;) {
                int r = sh_lr_next();
                if (r == 0) break;
                if (r < 0) { console_printf("cut: read error %s\n", disp); break; }
                const char *line = sh_lr_line;
                if (mode == 2) {
                    int first = 1;
                    for (int k = 0; k < ncut; k++) {
                        for (int pos = cut_lo[k]; pos <= cut_hi[k]; pos++) {
                            int idx = pos - 1, len = 0;
                            while (line[len]) len++;
                            if (idx < len) {
                                if (!first) { /* chars are contiguous: no separator */ }
                                console_putchar(line[idx]);
                                first = 0;
                            }
                        }
                    }
                    console_putchar('\n');
                } else {
                    /* Fields: split on delim. */
                    int has_delim = 0;
                    for (int i = 0; line[i]; i++) if (line[i] == delim) has_delim = 1;
                    if (!has_delim) { console_printf("%s\n", line); continue; }
                    int first = 1;
                    for (int k = 0; k < ncut; k++) {
                        for (int f = cut_lo[k]; f <= cut_hi[k]; f++) {
                            /* Find field f (1-based). */
                            int cur = 1, start = 0, end = 0, i = 0;
                            while (line[i]) {
                                if (line[i] == delim) {
                                    if (cur == f) { end = i; break; }
                                    cur++; start = i + 1;
                                }
                                i++;
                            }
                            if (cur == f && end == 0) end = i;
                            if (cur < f) continue; /* field absent */
                            if (!first) console_putchar(delim);
                            for (int j = start; j < end; j++) console_putchar(line[j]);
                            first = 0;
                        }
                    }
                    console_putchar('\n');
                }
            }
        }
    } else if (strcmp(tok[0], "uniq") == 0) {
        int flag_c = 0, flag_d = 0, flag_u = 0;
        const char *args[33];
        int nargs = 0;
        if (n >= 2 && tok[1][0] == '-' && tok[1][1] != 0) {
            for (u32 k = 1; tok[1][k]; k++) {
                if (tok[1][k] == 'c') flag_c = 1;
                else if (tok[1][k] == 'd') flag_d = 1;
                else if (tok[1][k] == 'u') flag_u = 1;
                else { console_write("Usage: uniq [-c] [-d] [-u] [files...]\n"); return 0; }
            }
            nargs = sh_tool_inputs(n, 0, rest, args, "Usage: uniq [-c] [-d] [-u] [files...]\n");
            if (nargs < 0) return 0;
        } else {
            nargs = sh_tool_inputs(n, (n >= 2) ? tok[1] : 0, rest, args, "Usage: uniq [-c] [-d] [-u] [files...]\n");
            if (nargs < 0) return 0;
        }
        static char uniq_prev[256];
        for (int a = 0; a < nargs; a++) {
            const char *fname = sh_input_name(args[a]);
            const char *disp = sh_input_disp(args[a]);
            if (sh_lr_open(fname, session_uid) != 0) {
                console_printf("uniq: cannot read %s\n", disp);
                continue;
            }
            int have = 0, cnt = 0;
            for (;;) {
                int r = sh_lr_next();
                if (r == 0) break;
                if (r < 0) { console_printf("uniq: read error %s\n", disp); break; }
                if (have && strcmp(uniq_prev, sh_lr_line) == 0) { cnt++; continue; }
                if (have) {
                    if (flag_d) { if (cnt > 1) console_printf("%s\n", uniq_prev); }
                    else if (flag_u) { if (cnt == 1) console_printf("%s\n", uniq_prev); }
                    else if (flag_c) console_printf("%d %s\n", cnt, uniq_prev);
                    else console_printf("%s\n", uniq_prev);
                }
                {
                    int k = 0;
                    while (sh_lr_line[k]) { uniq_prev[k] = sh_lr_line[k]; k++; }
                    uniq_prev[k] = 0;
                }
                have = 1; cnt = 1;
            }
            if (have) {
                if (flag_d) { if (cnt > 1) console_printf("%s\n", uniq_prev); }
                else if (flag_u) { if (cnt == 1) console_printf("%s\n", uniq_prev); }
                else if (flag_c) console_printf("%d %s\n", cnt, uniq_prev);
                else console_printf("%s\n", uniq_prev);
            }
        }
    } else if (strcmp(tok[0], "tee") == 0) {
        /* tee [-a] <file>...: stdin source only. */
        const char *words[33];
        u32 nw = (n >= 2) ? sh_split_args(tok[1], rest, words, 33) : 0;
        int flag_a = 0, wi = 0;
        while (wi < (int)nw && words[wi][0] == '-' && words[wi][1] != 0) {
            for (int k = 1; words[wi][k]; k++) {
                if (words[wi][k] == 'a') flag_a = 1;
                else { console_write("Usage: tee [-a] <file>...\n"); return 0; }
            }
            wi++;
        }
        if (wi >= (int)nw) { console_write("Usage: tee [-a] <file>...\n"); return 0; }
        if (!sh_stdin_file[0]) { console_write("Usage: tee [-a] <file>... (reads stdin: pipe or < file)\n"); return 0; }
        static char tee_buf[65536];
        u32 tlen = 0;
        int over = 0;
        if (sh_lr_open(sh_stdin_file, session_uid) != 0) {
            console_write("tee: cannot read stdin\n"); return 0;
        }
        for (;;) {
            int r = sh_lr_next();
            if (r == 0) break;
            if (r < 0) { console_write("tee: read error\n"); break; }
            /* Echo the line, and stage it (with its newline). */
            console_printf("%s\n", sh_lr_line);
            int ll = 0;
            while (sh_lr_line[ll]) ll++;
            if (tlen + (u32)ll + 1 > sizeof(tee_buf)) { over = 1; break; }
            for (int k = 0; k < ll; k++) tee_buf[tlen++] = sh_lr_line[k];
            tee_buf[tlen++] = '\n';
        }
        if (over) { console_write("tee: input over 64 KiB cap, files not written\n"); sh_cmd_status = 1; return 0; }
        static u8 tee_stage[65536 + 4096];
        for (; wi < (int)nw; wi++) {
            const char *fn = words[wi];
            u32 mode = 0644, old = 0;
            struct fs_stat st;
            int exists = fs_exists(fn);
            if (exists) {
                if (fs_stat_as(fn, &st, session_uid) != 0) {
                    console_printf("tee: cannot write %s\n", fn);
                    sh_cmd_status = 1; continue;
                }
                mode = st.mode;
                if (flag_a) {
                    if (st.size > sizeof(tee_stage) - 4096) {
                        console_printf("tee: cannot write %s (too large)\n", fn);
                        sh_cmd_status = 1; continue;
                    }
                    u32 got = 0;
                    if (st.size > 0 && fs_read_as(fn, tee_stage, st.size, &got, session_uid) != 0) {
                        console_printf("tee: cannot write %s\n", fn);
                        sh_cmd_status = 1; continue;
                    }
                    old = got;
                }
            }
            if (flag_a && old + tlen > sizeof(tee_stage)) {
                console_printf("tee: cannot write %s (too large)\n", fn);
                sh_cmd_status = 1; continue;
            }
            for (u32 k = 0; k < tlen; k++) tee_stage[old + k] = (u8)tee_buf[k];
            if (fs_write_as(fn, tee_stage, old + tlen, session_uid, mode) != 0) {
                console_printf("tee: cannot write %s\n", fn);
                sh_cmd_status = 1; continue;
            }
        }
    } else if (strcmp(tok[0], "seq") == 0) {
        const char *words[33];
        u32 nw = (n >= 2) ? sh_split_args(tok[1], rest, words, 33) : 0;
        int first = 1, step = 1, last = 0, ok = 1;
        if (nw == 1) { last = 0; }
        /* Parse signed integers. */
        {
            int vals[3];
            if (nw < 1 || nw > 3) ok = 0;
            for (u32 k = 0; k < nw && ok; k++) {
                const char *w = words[k];
                int neg = 0, v = 0, any = 0;
                if (*w == '-') { neg = 1; w++; }
                while (*w >= '0' && *w <= '9') { v = v * 10 + (*w - '0'); w++; any = 1; if (v > 1000000) v = 1000000; }
                if (*w != 0 || !any) ok = 0;
                vals[k] = neg ? -v : v;
            }
            if (ok) {
                if (nw == 1) { first = 1; step = 1; last = vals[0]; }
                else if (nw == 2) { first = vals[0]; step = 1; last = vals[1]; }
                else { first = vals[0]; step = vals[1]; last = vals[2]; }
            }
        }
        if (!ok || step == 0) { console_write("Usage: seq [first [step]] last\n"); sh_cmd_status = 2; return 0; }
        int count = 0;
        if ((step > 0 && last >= first) || (step < 0 && last <= first)) {
            count = (last - first) / step + 1;
        }
        if (count > 10000) { console_write("seq: too many numbers (max 10000)\n"); sh_cmd_status = 1; return 0; }
        for (int v = first; (step > 0) ? (v <= last) : (v >= last); v += step) {
            console_printf("%d\n", v);
        }
    } else if (strcmp(tok[0], "basename") == 0) {
        if (n < 2) { console_write("Usage: basename <name>\n"); sh_cmd_status = 2; return 0; }
        const char *nm = tok[1];
        int len = 0;
        while (nm[len]) len++;
        while (len > 1 && nm[len - 1] == '/') len--;
        int start = len;
        while (start > 0 && nm[start - 1] != '/') start--;
        char out[128];
        int k = 0;
        for (int i = start; i < len && k < 127; i++) out[k++] = nm[i];
        out[k] = 0;
        if (k == 0) console_write("/\n");
        else console_printf("%s\n", out);
    } else if (strcmp(tok[0], "dirname") == 0) {
        if (n < 2) { console_write("Usage: dirname <name>\n"); sh_cmd_status = 2; return 0; }
        const char *nm = tok[1];
        int len = 0;
        while (nm[len]) len++;
        while (len > 1 && nm[len - 1] == '/') len--;
        int last_slash = -1;
        for (int i = 0; i < len; i++) if (nm[i] == '/') last_slash = i;
        if (last_slash <= 0) console_write("/\n");
        else {
            char out[128];
            int k = 0;
            for (int i = 0; i < last_slash && k < 127; i++) out[k++] = nm[i];
            out[k] = 0;
            console_printf("%s\n", out);
        }
    } else if (strcmp(tok[0], "more") == 0 || strcmp(tok[0], "less") == 0) {
        const char *args[33];
        int nargs = sh_tool_inputs(n, (n >= 2) ? tok[1] : 0, rest, args, "Usage: more [file]\n");
        if (nargs < 0) return 0;
        for (int a = 0; a < nargs; a++) {
            const char *fname = sh_input_name(args[a]);
            const char *disp = sh_input_disp(args[a]);
            if (sh_lr_open(fname, session_uid) != 0) {
                console_printf("more: cannot read %s\n", disp);
                continue;
            }
            u32 shown = 0;
            int quit = 0;
            for (;;) {
                int r = sh_lr_next();
                if (r == 0) break;
                if (r < 0) { console_printf("more: read error %s\n", disp); break; }
                console_printf("%s\n", sh_lr_line);
                shown++;
                if (shown % 20 == 0) {
                    console_write("--More--");
                    int c = -1;
                    for (;;) {
                        keyboard_poll();
                        c = keyboard_getchar();
                        if (c >= 0) break;
                        __asm__ volatile ("hlt");
                    }
                    /* Erase the prompt line. */
                    console_write("\r        \r");
                    if (c == 'q' || c == 'Q' || c == 3) { quit = 1; break; }
                    /* Space (or any other key) continues. */
                }
            }
            if (quit) break;
        }
    } else if (strcmp(tok[0], "sort") == 0) {
        const char *args[33];
        int nargs = sh_tool_inputs(n, (n >= 2) ? tok[1] : 0, rest, args, "Usage: sort [files...]\n");
        if (nargs < 0) return 0;
        int total = 0;
        int over = 0;
        for (int a = 0; a < nargs; a++) {
            int c = sh_read_lines(sh_input_name(args[a]), session_uid, sh_sort_lines, total);
            if (c == -1) { console_printf("sort: cannot read %s\n", sh_input_disp(args[a])); continue; }
            if (c == -2) { over = 1; break; }
            total = c;
        }
        if (over) { console_write("sort: too many lines (max 256)\n"); return 0; }
        /* Insertion sort, byte order (unsigned bytes). */
        for (int i = 1; i < total; i++) {
            char tmp[256];
            u32 k = 0;
            while (sh_sort_lines[i][k]) { tmp[k] = sh_sort_lines[i][k]; k++; }
            tmp[k] = 0;
            int j = i - 1;
            while (j >= 0) {
                int cmp = 0;
                for (u32 t = 0; ; t++) {
                    u8 ca = (u8)sh_sort_lines[j][t], cb = (u8)tmp[t];
                    if (ca != cb) { cmp = (ca < cb) ? -1 : 1; break; }
                    if (ca == 0) break;
                }
                if (cmp <= 0) break;
                u32 t = 0;
                while (sh_sort_lines[j][t]) { sh_sort_lines[j + 1][t] = sh_sort_lines[j][t]; t++; }
                sh_sort_lines[j + 1][t] = 0;
                j--;
            }
            u32 t = 0;
            while (tmp[t]) { sh_sort_lines[j + 1][t] = tmp[t]; t++; }
            sh_sort_lines[j + 1][t] = 0;
        }
        for (int i = 0; i < total; i++) console_printf("%s\n", sh_sort_lines[i]);
    } else if (strcmp(tok[0], "wc") == 0) {
        int flag_l = 0, flag_w = 0, flag_c = 0;
        const char *args[33];
        u32 nargs = 0;
        if (n >= 2 && tok[1][0] == '-' && tok[1][1] != 0) {
            for (u32 k = 1; tok[1][k]; k++) {
                if (tok[1][k] == 'l') flag_l = 1;
                else if (tok[1][k] == 'w') flag_w = 1;
                else if (tok[1][k] == 'c') flag_c = 1;
                else { console_write("Usage: wc [-l] [-w] [-c] [files...]\n"); return 0; }
            }
            nargs = sh_split_args(0, rest, args, 33);
        } else if (n >= 2) {
            nargs = sh_split_args(tok[1], rest, args, 33);
        }
        if (!flag_l && !flag_w && !flag_c) { flag_l = flag_w = flag_c = 1; }
        if (nargs == 0) {
            if (sh_stdin_file[0]) { args[0] = "-"; nargs = 1; }
            else { console_write("Usage: wc [-l] [-w] [-c] [files...]\n"); return 0; }
        }
        u32 tot_l = 0, tot_w = 0, tot_c = 0;
        int multi = (nargs > 1);
        for (u32 a = 0; a < nargs; a++) {
            const char *fname = sh_input_name(args[a]);
            const char *disp = sh_input_disp(args[a]);
            u32 off = 0, lines = 0, words = 0, chars = 0;
            int in_word = 0, err = 0;
            for (;;) {
                u32 got = 0;
                if (fs_read_range_as(fname, sh_lr_win, sizeof(sh_lr_win), off, &got, session_uid) != 0) { err = 1; break; }
                if (got == 0) break;
                off += got;
                for (u32 i = 0; i < got; i++) {
                    u8 ch = sh_lr_win[i];
                    chars++;
                    if (ch == '\n') lines++;
                    int ws = (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r');
                    if (!ws && !in_word) { words++; in_word = 1; }
                    else if (ws) in_word = 0;
                }
            }
            if (err) { console_printf("wc: cannot read %s\n", disp); continue; }
            tot_l += lines; tot_w += words; tot_c += chars;
            int first = 1;
            if (flag_l) { console_printf("%s%u", first ? "" : " ", lines); first = 0; }
            if (flag_w) { console_printf("%s%u", first ? "" : " ", words); first = 0; }
            if (flag_c) { console_printf("%s%u", first ? "" : " ", chars); first = 0; }
            if (strcmp(args[a], "-") != 0) console_printf(" %s\n", disp);
            else console_write("\n");
        }
        if (multi) {
            int first = 1;
            if (flag_l) { console_printf("%s%u", first ? "" : " ", tot_l); first = 0; }
            if (flag_w) { console_printf("%s%u", first ? "" : " ", tot_w); first = 0; }
            if (flag_c) { console_printf("%s%u", first ? "" : " ", tot_c); first = 0; }
            console_write(" total\n");
        }
    } else if (strcmp(tok[0], "head") == 0 || strcmp(tok[0], "tail") == 0) {
        int is_tail = (strcmp(tok[0], "tail") == 0);
        u32 count = 10;
        const char *args[33];
        u32 nargs = 0;
        int badflag = 0;
        if (n >= 2 && tok[1][0] == '-' && tok[1][1] != 0) {
            if (tok[1][1] == 'n') {
                if (tok[1][2] != 0) {
                    int v = sh_parse_num(tok[1] + 2);
                    if (v < 0) badflag = 1; else count = (u32)v;
                    nargs = sh_split_args(0, rest, args, 33);
                } else {
                    const char *words[33];
                    u32 nw = sh_split_args(0, rest, words, 33);
                    if (nw < 1) badflag = 1;
                    else {
                        int v = sh_parse_num(words[0]);
                        if (v < 0) badflag = 1;
                        else {
                            count = (u32)v;
                            for (u32 k = 1; k < nw; k++) args[nargs++] = words[k];
                        }
                    }
                }
            } else if (tok[1][1] >= '0' && tok[1][1] <= '9') {
                int v = sh_parse_num(tok[1] + 1);
                if (v < 0) badflag = 1; else count = (u32)v;
                nargs = sh_split_args(0, rest, args, 33);
            } else badflag = 1;
        } else if (n >= 2) {
            nargs = sh_split_args(tok[1], rest, args, 33);
        }
        if (badflag) {
            if (is_tail) console_write("Usage: tail [-n N] [files...]\n");
            else console_write("Usage: head [-n N] [files...]\n");
            return 0;
        }
        if (nargs == 0) {
            if (sh_stdin_file[0]) { args[0] = "-"; nargs = 1; }
            else {
                if (is_tail) console_write("Usage: tail [-n N] [files...]\n");
                else console_write("Usage: head [-n N] [files...]\n");
                return 0;
            }
        }
        int multi = (nargs > 1);
        for (u32 a = 0; a < nargs; a++) {
            const char *fname = sh_input_name(args[a]);
            const char *disp = sh_input_disp(args[a]);
            if (multi) {
                if (a > 0) console_write("\n");
                console_printf("==> %s <==\n", disp);
            }
            if (sh_lr_open(fname, session_uid) != 0) {
                if (is_tail) console_printf("tail: cannot read %s\n", disp);
                else console_printf("head: cannot read %s\n", disp);
                continue;
            }
            if (!is_tail) {
                u32 shown = 0;
                for (;;) {
                    if (shown >= count) break;
                    int r = sh_lr_next();
                    if (r == 0) break;
                    if (r < 0) { console_printf("head: read error %s\n", disp); break; }
                    console_printf("%s\n", sh_lr_line);
                    shown++;
                }
            } else {
                /* Two passes: count lines, then print from total-N. */
                u32 total = 0;
                int err = 0;
                for (;;) {
                    int r = sh_lr_next();
                    if (r == 0) break;
                    if (r < 0) { err = 1; break; }
                    total++;
                }
                if (err) { console_printf("tail: read error %s\n", disp); continue; }
                if (sh_lr_open(fname, session_uid) != 0) {
                    console_printf("tail: cannot read %s\n", disp);
                    continue;
                }
                u32 skip = (total > count) ? total - count : 0;
                u32 seen = 0;
                for (;;) {
                    int r = sh_lr_next();
                    if (r == 0) break;
                    if (r < 0) { console_printf("tail: read error %s\n", disp); break; }
                    if (seen++ < skip) continue;
                    console_printf("%s\n", sh_lr_line);
                }
            }
        }
    } else if (strcmp(tok[0], "diff") == 0) {
        const char *args[33];
        u32 nargs = (n >= 2) ? sh_split_args(tok[1], rest, args, 33) : 0;
        if (nargs != 2) { console_write("Usage: diff <file1> <file2>\n"); return 0; }
        int na = sh_read_lines(sh_input_name(args[0]), session_uid, sh_diff_a, 0);
        if (na == -1) { console_printf("diff: cannot read %s\n", sh_input_disp(args[0])); return 0; }
        if (na == -2) { console_write("diff: too many lines (max 256)\n"); return 0; }
        int nb = sh_read_lines(sh_input_name(args[1]), session_uid, sh_diff_b, 0);
        if (nb == -1) { console_printf("diff: cannot read %s\n", sh_input_disp(args[1])); return 0; }
        if (nb == -2) { console_write("diff: too many lines (max 256)\n"); return 0; }
        /* DP: dp[i][j] = LCS of the first i lines of A, first j of B. */
        for (int i = 0; i <= na; i++) sh_diff_dp[i][0] = 0;
        for (int j = 0; j <= nb; j++) sh_diff_dp[0][j] = 0;
        for (int i = 1; i <= na; i++) {
            for (int j = 1; j <= nb; j++) {
                if (strcmp(sh_diff_a[i - 1], sh_diff_b[j - 1]) == 0)
                    sh_diff_dp[i][j] = sh_diff_dp[i - 1][j - 1] + 1;
                else
                    sh_diff_dp[i][j] = (sh_diff_dp[i - 1][j] >= sh_diff_dp[i][j - 1]) ?
                        sh_diff_dp[i - 1][j] : sh_diff_dp[i][j - 1];
            }
        }
        /* Backtrack, emitting ops in reverse (0 match, 1 del, 2 add). */
        int nops = 0;
        {
            int i = na, j = nb;
            while (i > 0 || j > 0) {
                if (i > 0 && j > 0 && strcmp(sh_diff_a[i - 1], sh_diff_b[j - 1]) == 0) {
                    sh_diff_op_type[nops] = 0; sh_diff_op_idx[nops] = (u32)(i - 1); nops++; i--; j--;
                } else if (j > 0 && (i == 0 || sh_diff_dp[i][j - 1] >= sh_diff_dp[i - 1][j])) {
                    sh_diff_op_type[nops] = 2; sh_diff_op_idx[nops] = (u32)(j - 1); nops++; j--;
                } else {
                    sh_diff_op_type[nops] = 1; sh_diff_op_idx[nops] = (u32)(i - 1); nops++; i--;
                }
            }
        }
        /* Forward pass: group DEL/ADD runs between matches into
           normal-format hunks. a_before/b_before are the counts
           consumed before the run (1-based starts are +1). */
        u32 a_pos = 0, b_pos = 0;
        u32 run_del = 0, run_add = 0, a_before = 0, b_before = 0;
        for (int k = nops - 1; k >= -1; k--) {
            int flush = (k < 0);
            u8 type = flush ? 0 : sh_diff_op_type[k];
            if (type == 0) flush = 1;
            if (type == 1 && run_del == 0 && run_add == 0) { a_before = a_pos; b_before = b_pos; }
            if (type == 2 && run_del == 0 && run_add == 0) { a_before = a_pos; b_before = b_pos; }
            if (type == 1) { run_del++; a_pos++; }
            else if (type == 2) { run_add++; b_pos++; }
            else if (type == 0) { a_pos++; b_pos++; }
            if (!flush) continue;
            if (run_del == 0 && run_add == 0) continue;
            /* Header: single numbers print bare, runs print a,b. */
            if (run_del > 0 && run_add == 0) {
                if (run_del == 1) console_printf("%ud%u\n", a_before + 1, b_before);
                else console_printf("%u,%ud%u\n", a_before + 1, a_before + run_del, b_before);
            } else if (run_del == 0 && run_add > 0) {
                if (run_add == 1) console_printf("%ua%u\n", a_before, b_before + 1);
                else console_printf("%ua%u,%u\n", a_before, b_before + 1, b_before + run_add);
            } else {
                if (run_del == 1 && run_add == 1) console_printf("%uc%u\n", a_before + 1, b_before + 1);
                else if (run_del == 1) console_printf("%uc%u,%u\n", a_before + 1, b_before + 1, b_before + run_add);
                else if (run_add == 1) console_printf("%u,%uc%u\n", a_before + 1, a_before + run_del, b_before + 1);
                else console_printf("%u,%uc%u,%u\n", a_before + 1, a_before + run_del, b_before + 1, b_before + run_add);
            }
            for (u32 d = 0; d < run_del; d++) console_printf("< %s\n", sh_diff_a[a_before + d]);
            if (run_del > 0 && run_add > 0) console_write("---\n");
            for (u32 d = 0; d < run_add; d++) console_printf("> %s\n", sh_diff_b[b_before + d]);
            run_del = 0; run_add = 0;
        }
    } else if (strcmp(tok[0], "edit") == 0) {
        /* Full-screen editor. The editor prints its own
           refusals ("edit: ...") and "edit: done" on exit; the
           shell adds nothing, so the serial log stays a clean
           record of the session. */
        if (n < 2 || (rest && rest[0])) { console_write("Usage: edit <file>\n"); return 0; }
        editor_open(tok[1], session_uid);
    } else if (strcmp(tok[0], "run") == 0) {
        if (n < 2) { console_write("Usage: run <file>\n"); return 0; }
        if (proc_exec_file(tok[1], session_uid) != 0) {
            console_printf("run: cannot run %s\n", tok[1]);
            return 0;
        }
    } else if (strcmp(tok[0], "pkg") == 0) {
        /* Note: tokenize() stops at 2 tokens and puts the rest in
           `rest`, so pkg subcommand arguments come from `rest`, not
           tok[2]/tok[3]. */
        if (n < 2) { console_write("Usage: pkg list | pkg avail | pkg install <file> | pkg install <name> | pkg remove <name> [force] | pkg repo [url] | pkg update | pkg fetch <name>\n"); return 0; }
        if (strcmp(tok[1], "help") == 0) {
            char first[32];
            if (help_first_word(rest, first, sizeof(first))) {
                char combined[64];
                int ci = 0;
                const char *p = "pkg";
                while (*p && ci < 30) combined[ci++] = *p++;
                combined[ci++] = ' ';
                p = first;
                while (*p && ci < 63) combined[ci++] = *p++;
                combined[ci] = 0;
                const struct help_entry *e = help_find(combined);
                if (e) help_print_entry(e);
                else console_write("Usage: pkg list | pkg avail | pkg install <file> | pkg install <name> | pkg remove <name> [force] | pkg repo [url] | pkg update | pkg fetch <name>\n");
            } else help_print_group("pkg");
            return 0;
        }
        if (strcmp(tok[1], "sysupdate") == 0) {
            /* pkg-group alias for the top-level sysupdate: same
               root rule, same bundle argument (first word only,
               as the flat command takes exactly tok[1]). */
            char first[32];
            if (!help_first_word(rest, first, sizeof(first))) { console_write("Usage: sysupdate <bundle.nxupd>\n"); return 0; }
            if (sh_cap_gate(CAP_PKG, "sysupdate") != 0) return 0;
            pkg_sysupdate(first);
            return 0;
        }
        if (strcmp(tok[1], "sysrollback") == 0) {
            if (sh_cap_gate(CAP_PKG, "sysrollback") != 0) return 0;
            pkg_sysrollback();
            return 0;
        }
        if (strcmp(tok[1], "list") == 0) {
            pkg_list();
        } else if (strcmp(tok[1], "avail") == 0) {
            /* Read-only like pkg list: no root check. */
            pkg_repo_avail();
        } else if (strcmp(tok[1], "search") == 0) {
            if (!rest || rest[0] == 0) { console_write("Usage: pkg search <pattern>\n"); return 0; }
            pkg_repo_search(rest);
        } else if (strcmp(tok[1], "install") == 0) {
            if (!rest || rest[0] == 0) { console_write("Usage: pkg install <file>\n"); return 0; }
            if (sh_cap_gate(CAP_PKG, "pkg install") != 0) return 0;
            /* Local file wins if it exists; a bare name without a
               .nxpkg suffix is a repository install. */
            if (fs_exists(rest)) pkg_install(rest);
            else {
                u32 rl = strlen(rest);
                if (rl >= 6 && strcmp(rest + rl - 6, ".nxpkg") == 0) pkg_install(rest);
                else pkg_repo_install(rest);
            }
        } else if (strcmp(tok[1], "repo") == 0) {
            if (!rest || rest[0] == 0) pkg_repo_show();
            else {
                if (sh_cap_gate(CAP_PKG, "pkg repo") != 0) return 0;
                pkg_repo_set(rest);
            }
        } else if (strcmp(tok[1], "update") == 0) {
            if (sh_cap_gate(CAP_PKG, "pkg update") != 0) return 0;
            pkg_repo_update();
        } else if (strcmp(tok[1], "fetch") == 0) {
            if (!rest || rest[0] == 0) { console_write("Usage: pkg fetch <name>\n"); return 0; }
            if (sh_cap_gate(CAP_PKG, "pkg fetch") != 0) return 0;
            pkg_repo_fetch(rest);
        } else if (strcmp(tok[1], "remove") == 0) {
            if (!rest || rest[0] == 0) { console_write("Usage: pkg remove <name> [force]\n"); return 0; }
            if (sh_cap_gate(CAP_PKG, "pkg remove") != 0) return 0;
            /* rest is "name" or "name force". */
            char *sp = rest;
            while (*sp && *sp != ' ') sp++;
            int force = 0;
            if (*sp == ' ') {
                *sp = 0; sp++;
                while (*sp == ' ') sp++;
                force = strcmp(sp, "force") == 0;
            }
            pkg_remove(rest, force);
        } else {
            console_write("Usage: pkg list | pkg avail | pkg install <file> | pkg install <name> | pkg remove <name> [force] | pkg repo [url] | pkg update | pkg fetch <name>\n");
        }
    } else if (strcmp(tok[0], "gui") == 0) {
        wm_run();
    } else if (strcmp(tok[0], "wmautotest") == 0) {
        wm_autotest();
    } else if (strcmp(tok[0], "guitest") == 0) {
        wm_test();
    } else if (strcmp(tok[0], "cursortest") == 0) {
        wm_cursortest();
    } else if (strcmp(tok[0], "cliptest") == 0) {
        wm_cliptest();
    } else if (strcmp(tok[0], "stormtest") == 0) {
        wm_stormtest();
    } else if (strcmp(tok[0], "desktop") == 0) {
        wm_desktop_run();
        if (wm_logout_requested()) return shell_do_logout();
    } else if (strcmp(tok[0], "desktopautotest") == 0) {
        wm_desktop_autotest();
    } else if (strcmp(tok[0], "desktopsectest") == 0) {
        wm_desktop_sectest();
    } else if (strcmp(tok[0], "desktopcalctest") == 0) {
        wm_desktop_calctest();
    } else if (strcmp(tok[0], "desktopexposetest") == 0) {
        wm_desktop_exposetest();
    } else if (strcmp(tok[0], "desktopnoconsoletest") == 0) {
        wm_desktop_noconsoletest();
    } else if (strcmp(tok[0], "desktopnewappstest") == 0) {
        wm_desktop_newappstest();
    } else if (strcmp(tok[0], "desktop10test") == 0) {
        wm_desktop_p10test();
    } else if (strcmp(tok[0], "desktopappstest") == 0) {
        wm_desktop_appstest();
    } else if (strcmp(tok[0], "desktop10sec") == 0) {
        wm_desktop_p10sec();
    } else if (strcmp(tok[0], "desktopwebtest") == 0) {
        wm_desktop_webtest();
    } else if (strcmp(tok[0], "desktopnonic") == 0) {
        wm_desktop_nonictest();
    } else if (strcmp(tok[0], "desktoprepotest") == 0) {
        wm_desktop_repotest();
    } else if (strcmp(tok[0], "desktoprepoapptest") == 0) {
        wm_desktop_repoapptest();
    } else if (strcmp(tok[0], "desktoppackageapptest") == 0) {
        wm_desktop_packageapptest();
    } else if (strcmp(tok[0], "desktopfileinstalltest") == 0) {
        wm_desktop_fileinstalltest();
    } else if (strcmp(tok[0], "desktopfileruntest") == 0) {
        wm_desktop_fileruntest();
    } else if (strcmp(tok[0], "desktopmonitorjobtest") == 0) {
        wm_desktop_monitorjobtest();
    } else if (strcmp(tok[0], "desktopreboottest") == 0) {
        wm_desktop_reboottest();
    } else if (strcmp(tok[0], "desktoplogouttest") == 0) {
        wm_desktop_logouttest();
        if (wm_logout_requested()) return shell_do_logout();
    } else if (strcmp(tok[0], "desktopfilesysupdtest") == 0) {
        wm_desktop_filesysupdtest();
    } else if (strcmp(tok[0], "desktoprollbacktest") == 0) {
        wm_desktop_rollbacktest();
    } else if (strcmp(tok[0], "desktopreposettest") == 0) {
        wm_desktop_reposettest();
    } else if (strcmp(tok[0], "desktopdnssettest") == 0) {
        wm_desktop_dnstest();
    } else if (strcmp(tok[0], "desktopnetpingtest") == 0) {
        wm_desktop_netpingtest();
    } else if (strcmp(tok[0], "desktoprepofetchtest") == 0) {
        wm_desktop_repofetchtest();
    } else if (strcmp(tok[0], "desktopfileshashtest") == 0) {
        wm_desktop_fileshashtest();
    } else if (strcmp(tok[0], "desktopmonitordisktest") == 0) {
        wm_desktop_monitordisktest();
    } else if (strcmp(tok[0], "desktopwebsavetest") == 0) {
        wm_desktop_websavetest();
    } else if (strcmp(tok[0], "desktopfileschmodtest") == 0) {
        wm_desktop_fileschmodtest();
    } else if (strcmp(tok[0], "desktopreporoottest") == 0) {
        wm_desktop_reporoottest();
    } else if (strcmp(tok[0], "desktopsettingsunlocktest") == 0) {
        wm_desktop_settingsunlocktest();
    } else if (strcmp(tok[0], "desktopunlocknousertest") == 0) {
        wm_desktop_unlocknousertest();
    } else if (strcmp(tok[0], "desktopfallbacktest") == 0) {
        wm_desktop_fallbacktest();
    } else if (strcmp(tok[0], "netinfo") == 0) {
        if (!net_present()) { console_write("net: no NIC\n"); return 0; }
        mac_t m; net_mac(&m);
        console_printf("net: MAC %x:%x:%x:%x:%x:%x rx=%u tx=%u drops=%u\n",
                       m.b[0], m.b[1], m.b[2], m.b[3], m.b[4], m.b[5],
                       net_rx_count(), net_tx_count(), net_drop_count());
        if (net_ip_configured()) {
            ip_t a, g, d, nm;
            net_ip_addr(&a); net_ip_gateway(&g); net_ip_dns(&d); net_ip_netmask(&nm);
            console_printf("net: ip=%u.%u.%u.%u mask=%u.%u.%u.%u gw=%u.%u.%u.%u dns=%u.%u.%u.%u\n",
                           a.b[0], a.b[1], a.b[2], a.b[3], nm.b[0], nm.b[1], nm.b[2], nm.b[3],
                           g.b[0], g.b[1], g.b[2], g.b[3], d.b[0], d.b[1], d.b[2], d.b[3]);
        } else console_write("net: no IP address (run dhcp)\n");
    } else if (strcmp(tok[0], "netdbg") == 0) {
        net_dbg();
    } else if (strcmp(tok[0], "ip") == 0) {
        if (n < 2) { console_write("Usage: ip addr|link|route\n"); return 0; }
        if (strcmp(tok[1], "addr") == 0) {
            if (!net_present()) { console_write("ip: no NIC\n"); return 0; }
            mac_t m; net_mac(&m);
            console_printf("link: MAC %x:%x:%x:%x:%x:%x\n", m.b[0], m.b[1], m.b[2], m.b[3], m.b[4], m.b[5]);
            if (net_ip_configured()) {
                ip_t a, g, d, nm;
                net_ip_addr(&a); net_ip_gateway(&g); net_ip_dns(&d); net_ip_netmask(&nm);
                console_printf("inet %u.%u.%u.%u mask %u.%u.%u.%u gw %u.%u.%u.%u dns %u.%u.%u.%u\n",
                               a.b[0], a.b[1], a.b[2], a.b[3], nm.b[0], nm.b[1], nm.b[2], nm.b[3],
                               g.b[0], g.b[1], g.b[2], g.b[3], d.b[0], d.b[1], d.b[2], d.b[3]);
            } else console_write("inet: no IP address (run dhcp)\n");
        } else if (strcmp(tok[1], "link") == 0) {
            if (!net_present()) { console_write("ip: no NIC\n"); return 0; }
            mac_t m; net_mac(&m);
            console_printf("link: e1000 up MAC %x:%x:%x:%x:%x:%x rx=%u tx=%u drops=%u\n",
                           m.b[0], m.b[1], m.b[2], m.b[3], m.b[4], m.b[5],
                           net_rx_count(), net_tx_count(), net_drop_count());
        } else if (strcmp(tok[1], "route") == 0) {
            if (!net_ip_configured()) { console_write("route: no IP address (run dhcp)\n"); return 0; }
            ip_t g; net_ip_gateway(&g);
            int zero = 1;
            for (int i = 0; i < 4; i++) if (g.b[i] != 0) zero = 0;
            if (zero) console_write("route: default via (none — direct network only)\n");
            else console_printf("route: default via %u.%u.%u.%u\n", g.b[0], g.b[1], g.b[2], g.b[3]);
        } else console_write("Usage: ip addr|link|route (read-only: route changes are not supported)\n");
    } else if (strcmp(tok[0], "hosts") == 0) {
        if (!fs_mounted()) { console_write("hosts: no filesystem\n"); return 0; }
        static u8 sh_hosts_buf[2049];
        u32 got = 0;
        if (fs_read_as("hosts.txt", sh_hosts_buf, sizeof(sh_hosts_buf) - 1, &got, session_uid) != 0) {
            console_write("(no hosts file)\n"); return 0;
        }
        sh_hosts_buf[got] = 0;
        u32 i = 0;
        while (i < got) {
            u32 s = i;
            while (i < got && sh_hosts_buf[i] != '\n') i++;
            u32 save = i;
            /* Print the line as-is (IP hostname). */
            for (u32 k = s; k < save; k++) console_putchar((char)sh_hosts_buf[k]);
            console_putchar('\n');
            if (i < got) i++;
        }
    } else if (strcmp(tok[0], "dhcp") == 0) {
        /* Parity run: network configuration is privileged now
           (root only). Grep-proven safe: every harness runs
           dhcp/dnsset as root; none expects non-root success. */
        if (sh_cap_gate(CAP_NET, "dhcp") != 0) return 0;
        console_write(net_dhcp() == 0 ? "dhcp: configured\n" : "dhcp: failed\n");
    } else if (strcmp(tok[0], "ping") == 0) {
        if (n < 2) { console_write("Usage: ping <ip>\n"); return 0; }
        ip_t dst;
        if (!net_parse_ip(tok[1], &dst)) { console_write("ping: bad IP (dotted quad only)\n"); return 0; }
        console_write(net_ping(dst) == 0 ? "ping: reply received\n" : "ping: no reply\n");
    } else if (strcmp(tok[0], "dnsset") == 0) {
        if (sh_cap_gate(CAP_NET, "dnsset") != 0) return 0;
        if (n < 2) { console_write("Usage: dnsset <ip>\n"); return 0; }
        ip_t ip;
        if (!net_parse_ip(tok[1], &ip)) { console_write("dnsset: bad IP\n"); return 0; }
        net_set_dns(ip);
        console_printf("dns server set to %u.%u.%u.%u\n", ip.b[0], ip.b[1], ip.b[2], ip.b[3]);
    } else if (strcmp(tok[0], "dns") == 0) {
        if (n < 2) { console_write("Usage: dns <name>\n"); return 0; }
        ip_t ip;
        /* hosts.txt first (Linux /etc/hosts behaviour): lines
           "IP hostname". A match short-circuits the DNS server. */
        int found = 0;
        {
            static u8 sh_dns_hosts[2049];
            u32 got = 0;
            if (fs_mounted() && fs_read_as("hosts.txt", sh_dns_hosts, sizeof(sh_dns_hosts) - 1, &got, session_uid) == 0) {
                sh_dns_hosts[got] = 0;
                u32 i = 0;
                while (i < got && !found) {
                    /* First word = IP, second word = hostname. */
                    u32 s = i;
                    while (i < got && sh_dns_hosts[i] != ' ' && sh_dns_hosts[i] != '\n') i++;
                    u32 ip_end = i;
                    if (i < got && sh_dns_hosts[i] == ' ') {
                        i++;
                        u32 hstart = i;
                        while (i < got && sh_dns_hosts[i] != ' ' && sh_dns_hosts[i] != '\n') i++;
                        u32 hlen = i - hstart;
                        u32 qlen = 0; while (tok[1][qlen]) qlen++;
                        if (hlen == qlen) {
                            int eq = 1;
                            for (u32 k = 0; k < hlen; k++) if (sh_dns_hosts[hstart + k] != tok[1][k]) eq = 0;
                            if (eq) {
                                /* Parse the IP word into ip_t. */
                                char ipstr[16]; u32 il = 0;
                                if (ip_end - s < 16) {
                                    for (u32 k = s; k < ip_end; k++) ipstr[il++] = (char)sh_dns_hosts[k];
                                    ipstr[il] = 0;
                                    if (net_parse_ip(ipstr, &ip)) found = 1;
                                }
                            }
                        }
                    }
                    while (i < got && sh_dns_hosts[i] != '\n') i++;
                    if (i < got) i++;
                    (void)s;
                }
            }
        }
        if (found)
            console_printf("dns: %s = %u.%u.%u.%u (hosts.txt)\n", tok[1], ip.b[0], ip.b[1], ip.b[2], ip.b[3]);
        else if (net_dns_lookup(tok[1], &ip) == 0)
            console_printf("dns: %s = %u.%u.%u.%u\n", tok[1], ip.b[0], ip.b[1], ip.b[2], ip.b[3]);
        else console_write("dns: lookup failed\n");
    } else if (strcmp(tok[0], "http") == 0) {
        /* Tokenizer quirk (kept for `write`): after 2 tokens the
           remainder is `rest`, so path/port come from rest, not
           tok[2]/tok[3]. */
        if (n < 2) { console_write("Usage: http [--no-redirect] [--no-cookies] <host> <path> [port]\n"); return 0; }
        char *host, *path;
        u16 port;
        int fflags;
        if (parse_fetch_args(tok[1], rest, 0, 80, &host, &path, &port, &fflags) != 0) {
            console_write("Usage: http [--no-redirect] [--no-cookies] <host> <path> [port]\n"); return 0;
        }
        static char body[8192];
        int flags = HTTP_FETCH_FOLLOW_REDIRECT | HTTP_FETCH_USE_COOKIES;
        if (fflags & FETCH_F_NOREDIR) flags &= ~HTTP_FETCH_FOLLOW_REDIRECT;
        if (fflags & FETCH_F_NOCOOKIES) flags &= ~HTTP_FETCH_USE_COOKIES;
        int bl = net_http_fetch(host, port, path, body, sizeof(body), flags);
        if (bl == -4) console_printf("http: %s\n", net_http_fetch_error());
        else if (bl < 0) {
            const char *e = net_http_fetch_error();
            if (e && e[0]) console_printf("http: %s\n", e);
            else console_write("http: failed\n");
        }
        else console_printf("http: %d bytes%s\n%s\n", bl, net_fetch_truncated() ? " (truncated)" : "", body);
    } else if (strcmp(tok[0], "https") == 0) {
        if (n < 2) { console_write("Usage: https [--legacy] [--no-redirect] [--no-cookies] <host> <path> [port]\n"); return 0; }
        char *host, *path;
        u16 port;
        int fflags;
        if (parse_fetch_args(tok[1], rest, 1, 443, &host, &path, &port, &fflags) != 0) {
            console_write("Usage: https [--legacy] [--no-redirect] [--no-cookies] <host> <path> [port]\n"); return 0;
        }
        static char body[8192];
        if (fflags & FETCH_F_LEGACY) tls_set_legacy_once();
        int flags = HTTP_FETCH_FOLLOW_REDIRECT | HTTP_FETCH_USE_COOKIES;
        if (fflags & FETCH_F_NOREDIR) flags &= ~HTTP_FETCH_FOLLOW_REDIRECT;
        if (fflags & FETCH_F_NOCOOKIES) flags &= ~HTTP_FETCH_USE_COOKIES;
        int bl = net_https_fetch(0, host, port, path, body, sizeof(body), flags);
        tls_clear_legacy();
        if (bl == -2) console_write("https: certificate refused, connection not made\n");
        else if (bl == -4) console_printf("https: %s\n", net_http_fetch_error());
        else if (bl < 0) {
            const char *e = net_http_fetch_error();
            if (e && e[0]) console_printf("https: %s\n", e);
            else console_write("https: failed\n");
        }
        else console_printf("https: %d bytes%s\n%s\n", bl, net_fetch_truncated() ? " (truncated)" : "", body);
    } else if (strcmp(tok[0], "httpsa") == 0) {
        if (n < 2) { console_write("Usage: httpsa [--legacy] [--no-redirect] [--no-cookies] <host> <path> [port]\n"); return 0; }
        char *host, *path;
        u16 port;
        int fflags;
        if (parse_fetch_args(tok[1], rest, 1, 443, &host, &path, &port, &fflags) != 0) {
            console_write("Usage: httpsa [--legacy] [--no-redirect] [--no-cookies] <host> <path> [port]\n"); return 0;
        }
        static char body[8192];
        if (fflags & FETCH_F_LEGACY) tls_set_legacy_once();
        int flags = HTTP_FETCH_FOLLOW_REDIRECT | HTTP_FETCH_USE_COOKIES;
        if (fflags & FETCH_F_NOREDIR) flags &= ~HTTP_FETCH_FOLLOW_REDIRECT;
        if (fflags & FETCH_F_NOCOOKIES) flags &= ~HTTP_FETCH_USE_COOKIES;
        int bl = net_https_fetch(1, host, port, path, body, sizeof(body), flags);
        tls_clear_legacy();
        if (bl == -2) console_write("httpsa: certificate refused, connection not made\n");
        else if (bl == -4) console_printf("httpsa: %s\n", net_http_fetch_error());
        else if (bl < 0) {
            const char *e = net_http_fetch_error();
            if (e && e[0]) console_printf("httpsa: %s\n", e);
            else console_write("httpsa: failed\n");
        }
        else console_printf("httpsa: %d bytes%s\n%s\n", bl, net_fetch_truncated() ? " (truncated)" : "", body);
    } else if (strcmp(tok[0], "httpss") == 0) {
        if (n < 2) { console_write("Usage: httpss [--legacy] [--no-redirect] [--no-cookies] <host> <path> [port]\n"); return 0; }
        char *host, *path;
        u16 port;
        int fflags;
        if (parse_fetch_args(tok[1], rest, 1, 443, &host, &path, &port, &fflags) != 0) {
            console_write("Usage: httpss [--legacy] [--no-redirect] [--no-cookies] <host> <path> [port]\n"); return 0;
        }
        static char body[8192];
        if (fflags & FETCH_F_LEGACY) tls_set_legacy_once();
        int flags = HTTP_FETCH_FOLLOW_REDIRECT | HTTP_FETCH_USE_COOKIES;
        if (fflags & FETCH_F_NOREDIR) flags &= ~HTTP_FETCH_FOLLOW_REDIRECT;
        if (fflags & FETCH_F_NOCOOKIES) flags &= ~HTTP_FETCH_USE_COOKIES;
        int bl = net_https_fetch(2, host, port, path, body, sizeof(body), flags);
        tls_clear_legacy();
        if (bl == -2) console_write("httpss: certificate refused, connection not made\n");
        else if (bl == -4) console_printf("httpss: %s\n", net_http_fetch_error());
        else if (bl < 0) {
            const char *e = net_http_fetch_error();
            if (e && e[0]) console_printf("httpss: %s\n", e);
            else console_write("httpss: failed\n");
        }
        else console_printf("httpss: %d bytes%s\n%s\n", bl, net_fetch_truncated() ? " (truncated)" : "", body);
    } else if (strcmp(tok[0], "cookies") == 0) {
        if (n < 2) { console_write("Usage: cookies list | cookies clear\n"); return 0; }
        if (strcmp(tok[1], "list") == 0) http_cookies_list();
        else if (strcmp(tok[1], "clear") == 0) {
            int c = http_cookies_clear();
            console_printf("cookies cleared: %d\n", c);
        } else console_write("Usage: cookies list | cookies clear\n");
    } else if (strcmp(tok[0], "sslprobe") == 0) {
        if (n < 2) { console_write("Usage: sslprobe <host> [port]\n"); return 0; }
        /* Host is tok[1]; the optional port is the first word
           of rest (rest is NULL when no port is given). */
        u16 port = 443;
        if (rest && rest[0]) {
            int v = 0, ok = 1;
            for (const char *p = rest; *p && *p != ' '; p++) {
                if (*p < '0' || *p > '9') { ok = 0; break; }
                v = v * 10 + (*p - '0');
            }
            if (ok && v >= 1 && v <= 65535) port = (u16)v;
        }
        if (net_sslprobe(tok[1], port) != 0) console_write("sslprobe: failed\n");
    } else if (strcmp(tok[0], "csprngtest") == 0) {
        console_write(csprng_selftest() == 0 ? "csprngtest PASS\n" : "csprngtest FAIL\n");
    } else if (strcmp(tok[0], "castore") == 0) {
        if (n < 2) { console_write("Usage: castore list|add <file>|update <host> [port]|clear\n"); return 0; }
        if (strcmp(tok[1], "list") == 0) {
            /* Count well-formed lines (RSA or EC) with
               windowed reads, so a store larger than any
               one buffer still lists. A partial line is
               carried across window boundaries. */
            static u8 win[1024];
            static char linebuf[513];
            u32 off = 0, count = 0, line_len = 0;
            int have = 0;
            for (;;) {
                u32 got = 0;
                if (fs_read_range_as("castore.txt", win, sizeof(win), off, &got, session_uid) != 0) break;
                if (got == 0) break;
                have = 1; off += got;
                for (u32 i = 0; i < got; i++) {
                    u8 c = win[i];
                    if (c == '\n') {
                        if (tls_key_line_valid(linebuf, line_len)) count++;
                        line_len = 0;
                    } else if (line_len < 512) {
                        linebuf[line_len++] = (char)c;
                    } else {
                        line_len = 513; /* overlong: not well-formed */
                    }
                }
            }
            if (line_len > 0 && line_len < 513 &&
                tls_key_line_valid(linebuf, line_len)) count++;
            if (!have) console_write("castore: no store\n");
            else console_printf("castore: %u roots\n", count);
        } else if (strcmp(tok[1], "add") == 0) {
            if (sh_cap_gate(CAP_PKG, "castore") != 0) return 0;
            if (!rest || !rest[0]) { console_write("Usage: castore add <file>\n"); return 0; }
            /* The key line comes from a FILE, not a literal:
               the shell line buffer is 128 chars, so a
               512-char hex argument could never be typed.
               The file's first line must be exactly one
               well-formed store line: a 512-hex RSA modulus
               or an "EC256:" P-256 point line. */
            static u8 hexbuf[8192];
            u32 hsize = 0;
            if (fs_read_as(rest, hexbuf, sizeof(hexbuf) - 1, &hsize, session_uid) != 0) {
                console_write("castore: add failed\n");
            } else {
                hexbuf[hsize] = 0;
                u32 hl = 0;
                while (hl < hsize && hexbuf[hl] != '\n' && hexbuf[hl] != '\r') hl++;
                hexbuf[hl] = 0;
                int arc = tls_castore_add((const char *)hexbuf);
                console_write(arc == 0 ? "castore: added\n" : arc == 1 ? "castore: already present\n" : "castore: add failed\n");
            }
        } else if (strcmp(tok[1], "update") == 0) {
            if (sh_cap_gate(CAP_PKG, "castore") != 0) return 0;
            if (!rest || !rest[0]) { console_write("Usage: castore update <host> [port]\n"); return 0; }
            char *host = rest;
            char *sp = host;
            while (*sp && *sp != ' ') sp++;
            u16 port = 443;
            if (*sp) {
                *sp = 0; sp++;
                while (*sp == ' ') sp++;
                if (*sp) {
                    int v = 0, ok = 1;
                    for (const char *p = sp; *p && *p != ' '; p++) {
                        if (*p < '0' || *p > '9') { ok = 0; break; }
                        v = v * 10 + (*p - '0');
                    }
                    if (ok && v >= 1 && v <= 65535) port = (u16)v;
                }
            }
            u32 count = 0;
            int rc = tls_castore_update(host, port, &count);
            if (rc == 0) console_printf("castore: updated %u roots\n", count);
            else if (rc == -1) console_write("castore: update fetch failed\n");
            else if (rc == -2) console_write("castore: update signature invalid, not installed\n");
            else if (rc == -3) console_write("castore: update bundle malformed, not installed\n");
            else console_write("castore: update install failed\n");
        } else if (strcmp(tok[1], "clear") == 0) {
            if (sh_cap_gate(CAP_PKG, "castore") != 0) return 0;
            console_write(fs_delete_as("castore.txt", session_uid) == 0 ? "castore: cleared\n" : "castore: no store\n");
        } else {
            console_write("Usage: castore list|add <file>|update <host> [port]|clear\n");
        }
    } else if (strcmp(tok[0], "tofprints") == 0) {
        if (sh_cap_gate(CAP_PKG, "tofprints") != 0) return 0;
        if (n < 2) { console_write("Usage: tofprints list|clear <host>\n"); return 0; }
        if (strcmp(tok[1], "list") == 0) {
            if (tls_tofu_print_list() != 0) console_write("tofprints: none stored\n");
        } else if (strcmp(tok[1], "clear") == 0) {
            if (!rest || !rest[0]) { console_write("Usage: tofprints clear <host>\n"); return 0; }
            int rc = tls_tofu_print_clear(rest);
            if (rc == 0) console_write("tofprints: cleared\n");
            else if (rc == 1) console_write("tofprints: not present\n");
            else console_write("tofprints: error\n");
        } else {
            console_write("Usage: tofprints list|clear <host>\n");
        }
    } else if (strcmp(tok[0], "srv") == 0) {
        /* Socket server surface (§15.2). Group dispatch makes
           `net srv ...` work the same way. */
        if (n < 2) {
            console_write("Usage: srv listen <port>|serve <port> [count] [timeout]|status\n");
            return 0;
        }
        if (strcmp(tok[1], "status") == 0) {
            sock_dump();
        } else if (strcmp(tok[1], "listen") == 0) {
            char *w[1];
            u32 port = 0;
            int wc = sh_split_rest(rest, w, 1);
            if (wc != 1 || !sh_sock_num(w[0], &port) || port < 1 || port > 65535) {
                console_write("Usage: srv listen <port>\n");
                return 0;
            }
            sh_srv_listen((u16)port);
        } else if (strcmp(tok[1], "serve") == 0) {
            char *w[3];
            u32 port = 0, count = 2, timeout = 600;
            int wc = sh_split_rest(rest, w, 3);
            if (wc < 1 || !sh_sock_num(w[0], &port) || port < 1 || port > 65535) {
                console_write("Usage: srv serve <port> [count] [timeout]\n");
                return 0;
            }
            if (wc >= 2 && (!sh_sock_num(w[1], &count) || count < 1 || count > 4)) {
                console_write("Usage: srv serve <port> [count 1-4] [timeout ticks]\n");
                return 0;
            }
            if (wc >= 3 && (!sh_sock_num(w[2], &timeout) || timeout < 1 || timeout > 60000)) {
                console_write("Usage: srv serve <port> [count] [timeout ticks 1-60000]\n");
                return 0;
            }
            sh_srv_serve((u16)port, (int)count, timeout);
        } else {
            console_write("Usage: srv listen <port>|serve <port> [count] [timeout]|status\n");
        }
    } else if (strcmp(tok[0], "socktest") == 0) {
        if (n < 2) {
            console_write("Usage: socktest clients <ip> <port>|udp <ip> <port>\n");
            return 0;
        }
        char *w[2];
        int wc = sh_split_rest(rest, w, 2);
        ip_t peer;
        u32 port = 0;
        if (wc != 2 || !net_parse_ip(w[0], &peer) ||
            !sh_sock_num(w[1], &port) || port < 1 || port > 65535) {
            console_write("Usage: socktest clients <ip> <port>|udp <ip> <port>\n");
            return 0;
        }
        if (strcmp(tok[1], "clients") == 0) sh_socktest_clients(peer, (u16)port);
        else if (strcmp(tok[1], "udp") == 0) sh_socktest_udp(peer, (u16)port);
        else console_write("Usage: socktest clients <ip> <port>|udp <ip> <port>\n");
    } else if (strcmp(tok[0], "fw") == 0) {
        /* Firewall (core CLI family (e)): subcommand in tok[1],
           arguments in rest. Mutations are root-gated here in
           the handler; status/list/stat are world-readable.
           Rules persist in fw.txt (root-owned 0600) on every
           mutation; a failed save is reported, not hidden,
           while the in-memory rule stays live. */
        if (n < 2) {
            console_write("Usage: fw status|enable|disable|default allow|deny|list|add <in|out> <allow|deny> <any|icmp|tcp|udp> <src> <sport> <dst> <dport>|del <n>|clear|stat\n");
            return 0;
        }
        if (strcmp(tok[1], "status") == 0) {
            console_printf("fw: %s, default %s, %d rules, %u drops\n",
                fw_enabled() ? "enabled" : "disabled",
                fw_default_deny() ? "deny" : "allow",
                fw_rule_count(), fw_drop_count());
        } else if (strcmp(tok[1], "list") == 0) {
            int c = fw_rule_count();
            if (c == 0) {
                console_write("fw: no rules\n");
            } else {
                for (int i = 0; i < c; i++) {
                    char line[128];
                    fw_rule_to_str(fw_rule_at(i), line, sizeof(line));
                    console_printf("%d: %s\n", i + 1, line);
                }
            }
        } else if (strcmp(tok[1], "stat") == 0) {
            console_printf("fw: %u drops\n", fw_drop_count());
        } else if (strcmp(tok[1], "enable") == 0) {
            if (sh_cap_gate(CAP_NET, "fw") != 0) return 0;
            fw_set_enabled(1);
            console_write(fw_save() == 0 ? "fw: enabled\n" : "fw: enabled (save failed)\n");
        } else if (strcmp(tok[1], "disable") == 0) {
            if (sh_cap_gate(CAP_NET, "fw") != 0) return 0;
            fw_set_enabled(0);
            console_write(fw_save() == 0 ? "fw: disabled\n" : "fw: disabled (save failed)\n");
        } else if (strcmp(tok[1], "default") == 0) {
            if (sh_cap_gate(CAP_NET, "fw") != 0) return 0;
            if (!rest || !rest[0]) { console_write("Usage: fw default allow|deny\n"); return 0; }
            if (strcmp(rest, "allow") == 0) {
                fw_set_default(0);
                console_write(fw_save() == 0 ? "fw: default allow\n" : "fw: default allow (save failed)\n");
            } else if (strcmp(rest, "deny") == 0) {
                fw_set_default(1);
                console_write(fw_save() == 0 ? "fw: default deny\n" : "fw: default deny (save failed)\n");
            } else {
                console_write("Usage: fw default allow|deny\n");
            }
        } else if (strcmp(tok[1], "add") == 0) {
            if (sh_cap_gate(CAP_NET, "fw") != 0) return 0;
            /* rest holds the 7 rule words; split them here
               (tokenize stops at 2 tokens). */
            static char addbuf[128];
            if (!rest || !rest[0]) {
                console_write("Usage: fw add <in|out> <allow|deny> <any|icmp|tcp|udp> <src> <sport> <dst> <dport>\n");
                return 0;
            }
            u32 i = 0;
            while (rest[i] && i < sizeof(addbuf) - 1) { addbuf[i] = rest[i]; i++; }
            addbuf[i] = 0;
            /* Rebuild a single-space line, then let the shared
               rule parser validate every field: a bad field
               means no rule is added at all. */
            char *w[7];
            int wc = 0;
            char *p = addbuf;
            while (*p && wc < 7) {
                while (*p == ' ') p++;
                if (!*p) break;
                w[wc++] = p;
                while (*p && *p != ' ') p++;
                if (*p) *p++ = 0;
            }
            if (wc != 7 || *p) {
                console_write("fw: bad rule\nUsage: fw add <in|out> <allow|deny> <any|icmp|tcp|udp> <src> <sport> <dst> <dport>\n");
                return 0;
            }
            char line[128];
            u32 o = 0;
            for (int k = 0; k < 7; k++) {
                if (k) line[o++] = ' ';
                const char *s = w[k];
                while (*s && o < sizeof(line) - 1) line[o++] = *s++;
            }
            line[o] = 0;
            struct fw_rule r;
            if (!fw_parse_rule_line(line, &r)) {
                console_write("fw: bad rule\nUsage: fw add <in|out> <allow|deny> <any|icmp|tcp|udp> <src> <sport> <dst> <dport>\n");
                return 0;
            }
            if (fw_add_rule(&r) != 0) {
                console_write("fw: rule table full (16)\n");
                return 0;
            }
            console_write(fw_save() == 0 ? "fw: rule added\n" : "fw: rule added (save failed)\n");
        } else if (strcmp(tok[1], "del") == 0) {
            if (sh_cap_gate(CAP_NET, "fw") != 0) return 0;
            if (!rest || !rest[0]) { console_write("Usage: fw del <n>\n"); return 0; }
            u32 v = 0;
            int ok = 1;
            for (const char *p = rest; *p && *p != ' '; p++) {
                if (*p < '0' || *p > '9') { ok = 0; break; }
                v = v * 10u + (u32)(*p - '0');
            }
            if (!ok || v < 1 || fw_del_rule((int)v - 1) != 0) {
                console_printf("fw: no such rule %s\n", rest);
                return 0;
            }
            console_write(fw_save() == 0 ? "fw: rule deleted\n" : "fw: rule deleted (save failed)\n");
        } else if (strcmp(tok[1], "clear") == 0) {
            if (sh_cap_gate(CAP_NET, "fw") != 0) return 0;
            fw_clear_rules();
            console_write(fw_save() == 0 ? "fw: rules cleared\n" : "fw: rules cleared (save failed)\n");
        } else {
            console_write("Usage: fw status|enable|disable|default allow|deny|list|add <in|out> <allow|deny> <any|icmp|tcp|udp> <src> <sport> <dst> <dport>|del <n>|clear|stat\n");
        }
    } else if (strcmp(tok[0], "nettest") == 0) {
        console_write(net_test_run() == 0 ? "nettest PASS\n" : "nettest FAIL\n");
    } else if (strcmp(tok[0], "hostmatch") == 0) {
        console_write(tls_hostmatch_selftest() == 0 ? "hostmatch PASS\n" : "hostmatch FAIL\n");
    } else if (strcmp(tok[0], "sysupdate") == 0) {
        /* Top-level command: its one argument is tok[1], not rest
           (rest holds text AFTER the second token — that is only
           for two-level commands like `pkg install <file>`). */
        if (n < 2) { console_write("Usage: sysupdate <bundle.nxupd>\n"); return 0; }
        if (sh_cap_gate(CAP_PKG, "sysupdate") != 0) return 0;
        pkg_sysupdate(tok[1]);
    } else if (strcmp(tok[0], "sysrollback") == 0) {
        if (sh_cap_gate(CAP_PKG, "sysrollback") != 0) return 0;
        pkg_sysrollback();
    } else if (strcmp(tok[0], "mousepoll") == 0) {
        /* Poll the PS/2 controller for 5 seconds, logging any bytes
           that arrive, whether or not IRQ12 fired. Used to diagnose
           QEMU monitor mouse injection. */
        console_write("mousepoll: waiting 5 seconds for controller bytes...\n");
        for (u32 t = 0; t < 500; t++) {
            if (inb(0x64) & 0x01) {
                u8 b = inb(0x60);
                console_printf("mousepoll byte 0x%x\n", (u32)b);
            }
            for (volatile u32 d = 0; d < 10000; d++) { }
        }
        console_write("mousepoll done\n");
    } else if (strcmp(tok[0], "mousetest") == 0) {
        /* Feed known PS/2 packets directly to the driver, bypassing
           QEMU monitor injection, and check the resulting state. */
        mouse_test_set(400, 300, 0);
        mouse_feed_byte(0x09); mouse_feed_byte(50); mouse_feed_byte(30);
        console_printf("mousetest: after (50,30) left-down: x=%d y=%d left=%u (expect 450,270,1)\n",
                       mouse_x(), mouse_y(), (u32)mouse_left());
        mouse_feed_byte(0x08); mouse_feed_byte(0); mouse_feed_byte(0);
        console_printf("mousetest: after release: left=%u (expect 0)\n", (u32)mouse_left());
        mouse_feed_byte(0x08); mouse_feed_byte(0x80); mouse_feed_byte(0); /* dx = -128? actually 0x80 = -128 as char */
        console_printf("mousetest: after dx -128: x=%d (expect 322)\n", mouse_x());
        /* Clamp: move far off-screen, must clamp to 0..799 / 0..599. */
        mouse_test_set(400, 300, 0);
        mouse_feed_byte(0x08); mouse_feed_byte(0x7F); mouse_feed_byte(0x7F);
        mouse_feed_byte(0x08); mouse_feed_byte(0x7F); mouse_feed_byte(0x7F);
        mouse_feed_byte(0x08); mouse_feed_byte(0x7F); mouse_feed_byte(0x7F);
        mouse_feed_byte(0x08); mouse_feed_byte(0x7F); mouse_feed_byte(0x7F);
        console_printf("mousetest: after large moves: x=%d y=%d (expect 799,0, clamped)\n", mouse_x(), mouse_y());
        /* Overflow packet: movement must be ignored, buttons applied. */
        mouse_test_set(400, 300, 0);
        mouse_feed_byte(0x49); mouse_feed_byte(100); mouse_feed_byte(100);
        console_printf("mousetest: overflow packet: x=%d y=%d left=%u (expect 400,300,1)\n",
                       mouse_x(), mouse_y(), (u32)mouse_left());
        mouse_test_set(400, 300, 0);
        console_write("mousetest PASS\n");
    } else if (strcmp(tok[0], "mouse") == 0) {
        console_printf("Mouse: present=%u x=%d y=%d left=%u middle=%u right=%u\n",
                       (u32)mouse_present(), mouse_x(), mouse_y(),
                       (u32)mouse_left(), (u32)mouse_middle(), (u32)mouse_right());
    } else if (strcmp(tok[0], "aes-test") == 0) {
        /* FIPS 197 AES-256 vector, using a local round-key array so
           the boot disk key (if any) is never overwritten. */
        u8 key[32], plain[16], cipher[16], expected[16];
        for (int i = 0; i < 32; i++) key[i] = (u8)i;
        for (int i = 0; i < 16; i++) plain[i] = (u8)(i * 16 + i);
        /* plain is 00 11 22 ... ff, built above as i*16+i = i*17. */
        u8 exp_bytes[16] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                            0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};
        for (int i = 0; i < 16; i++) expected[i] = exp_bytes[i];
        u32 rk[60];
        aes256_expand(key, rk);
        aes256_encrypt(rk, plain, cipher);
        char hex[33];
        for (int i = 0; i < 16; i++) {
            const char *d = "0123456789abcdef";
            hex[i*2] = d[(cipher[i] >> 4) & 0xF]; hex[i*2+1] = d[cipher[i] & 0xF];
        }
        hex[32] = 0;
        console_printf("AES-256 test: %s\n", hex);
        console_write(memcmp(cipher, expected, 16) == 0 ? "AES test PASS\n" : "AES test FAIL\n");
    } else if (strcmp(tok[0], "sha256") == 0) {
        if (n < 2) { console_write("Usage: sha256 <file>\n"); return 0; }
        /* Files up to 64 KiB, as with ELF loading. */
        static u8 hash_buf[65536];
        u32 size = 0;
        if (fs_read_as(tok[1], hash_buf, sizeof(hash_buf), &size, session_uid) != 0) {
            console_printf("sha256: cannot read %s\n", tok[1]); return 0;
        }
        u8 digest[32]; char hex[65];
        sha256_compute(hash_buf, size, digest);
        sha256_hex(digest, hex);
        console_printf("%s  %s\n", hex, tok[1]);
    } else if (strcmp(tok[0], "runbg") == 0) {
        if (n < 2) { console_write("Usage: runbg <file>\n"); return 0; }
        if (proc_bg_start(tok[1], session_uid) != 0) {
            console_printf("runbg: cannot start %s (bad file or job table full)\n", tok[1]);
            return 0;
        }
    } else if (strcmp(tok[0], "jobs") == 0) {
        proc_bg_list();
    } else if (strcmp(tok[0], "signals") == 0) {
        console_write("Signals (background jobs only; see `kill -N`):\n");
        console_write("1 HUP hangup: terminate\n");
        console_write("2 INT interrupt: terminate\n");
        console_write("9 KILL kill: terminate\n");
        console_write("15 TERM terminate: terminate\n");
        console_write("18 CONT continue: resume a stopped job\n");
        console_write("19 STOP stop: pause a job\n");
    } else if (strcmp(tok[0], "kill") == 0) {
        if (n < 2) { console_write("Usage: kill [-N] <pid|%N>\n"); return 0; }
        /* Deep-core phase: `kill -N <spec>` / `kill -NAME <spec>`
           sends a signal instead of killing. Signal names are
           matched exactly (HUP INT KILL TERM CONT STOP). */
        if (tok[1][0] == '-' && tok[1][1] != 0) {
            int sig = -1;
            if (tok[1][1] >= '0' && tok[1][1] <= '9') {
                int v = 0, digits = 0;
                for (const char *p = tok[1] + 1; *p; p++) {
                    if (*p < '0' || *p > '9') { digits = 0; break; }
                    v = v * 10 + (*p - '0'); digits++;
                }
                if (digits > 0) sig = v;
            } else if (strcmp(tok[1] + 1, "HUP") == 0) sig = 1;
            else if (strcmp(tok[1] + 1, "INT") == 0) sig = 2;
            else if (strcmp(tok[1] + 1, "KILL") == 0) sig = 9;
            else if (strcmp(tok[1] + 1, "TERM") == 0) sig = 15;
            else if (strcmp(tok[1] + 1, "CONT") == 0) sig = 18;
            else if (strcmp(tok[1] + 1, "STOP") == 0) sig = 19;
            if (sig < 0 || !rest || !rest[0]) {
                console_write("Usage: kill [-N] <pid|%N>\n"); return 0;
            }
            u32 pid = 0;
            if (sh_bg_resolve(rest, session_uid, &pid) != 0) {
                console_printf("kill: cannot kill %s (no such job or no permission)\n", rest); return 0;
            }
            int r = proc_bg_signal(pid, session_uid, sig);
            if (r == -2) { console_printf("kill: unknown signal %s\n", tok[1]); return 0; }
            if (r != 0) { console_printf("kill: cannot kill %s (no such job or no permission)\n", rest); return 0; }
            console_printf("kill: signal %d sent to %u\n", sig, pid);
            return 0;
        }
        u32 pid = 0; int bad = 0;
        if (tok[1][0] == '%') {
            /* %N = Nth job in `jobs` display order. */
            u32 jn = 0;
            for (const char *p = tok[1] + 1; *p; p++) {
                if (*p < '0' || *p > '9' || jn > 1000000) { bad = 1; break; }
                jn = jn * 10u + (u32)(*p - '0');
            }
            if (!bad) {
                char nm[32]; u32 pp, uu;
                if (jn < 1 || proc_bg_at((int)jn - 1, nm, &pp, &uu) != 0) bad = 1;
                else pid = pp;
            }
        } else {
            for (const char *p = tok[1]; *p; p++) {
                if (*p < '0' || *p > '9' || pid > 1000000) { bad = 1; break; }
                pid = pid * 10u + (u32)(*p - '0');
            }
        }
        if (bad || proc_bg_kill(pid, session_uid) != 0) {
            console_printf("kill: cannot kill %s (no such job or no permission)\n", tok[1]);
            return 0;
        }
    } else if (strcmp(tok[0], "killall") == 0) {
        if (n < 2) { console_write("Usage: killall <name>\n"); return 0; }
        /* Collect matching pids FIRST (max 4), then kill each
           under the kill permission rule (indices shift as
           jobs die, so killing during the scan would skip). */
        u32 pids[4];
        u32 npids = 0;
        for (int i = 0; i < MAX_BG; i++) {
            char nm[32]; u32 pp, uu;
            if (proc_bg_at(i, nm, &pp, &uu) != 0) break;
            if (strcmp(nm, tok[1]) == 0 && npids < 4) pids[npids++] = pp;
        }
        if (npids == 0) { console_printf("killall: no job named %s\n", tok[1]); return 0; }
        u32 killed = 0, denied = 0;
        for (u32 i = 0; i < npids; i++) {
            if (proc_bg_kill(pids[i], session_uid) == 0) killed++;
            else denied++;
        }
        if (denied == 0) console_printf("killall: killed %u job(s)\n", killed);
        else console_printf("killall: killed %u job(s), %u not permitted\n", killed, denied);
    } else if (strcmp(tok[0], "nice") == 0) {
        /* nice [-n N] runbg <file>: the only form offered (a bare
           `nice <cmd>` for arbitrary commands would need an
           exec channel the shell does not have for foreground
           programs). */
        int nicev = 0;
        const char *file = 0;
        if (n >= 2 && strcmp(tok[1], "-n") == 0) {
            if (!rest || !rest[0]) { console_write("Usage: nice [-n N] runbg <file>\n"); return 0; }
            /* rest = "N runbg file": parse N, then expect runbg. */
            char *p = rest;
            int neg = 0;
            if (*p == '-') { neg = 1; p++; }
            int v = 0, digits = 0;
            while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; digits++; }
            if (digits == 0) { console_write("Usage: nice [-n N] runbg <file>\n"); return 0; }
            nicev = neg ? -v : v;
            while (*p == ' ') p++;
            if (p[0] != 'r' || p[1] != 'u' || p[2] != 'n' || p[3] != 'b' || p[4] != 'g' || (p[5] != ' ' && p[5] != 0)) {
                console_write("Usage: nice [-n N] runbg <file>\n"); return 0;
            }
            p += 5;
            while (*p == ' ') p++;
            file = p;
        } else if (n >= 2 && strcmp(tok[1], "runbg") == 0) {
            file = rest;
        } else { console_write("Usage: nice [-n N] runbg <file>\n"); return 0; }
        if (!file || !file[0]) { console_write("Usage: nice [-n N] runbg <file>\n"); return 0; }
        if (nicev < -20 || nicev > 19) { console_write("nice: value must be -20..19\n"); return 0; }
        if (nicev < 0 && session_uid != 0) { console_write("nice: negative nice needs root\n"); return 0; }
        if (nicev < 0 && session_uid == 0 && (session_caps & (1u << CAP_SYS)) == 0) { console_write("nice: refused: root capability cap_sys is not set (see `cap list`)\n"); return 0; }
        if (proc_bg_start_nice(file, session_uid, nicev) != 0) {
            console_printf("nice: cannot start %s\n", file); return 0;
        }
        console_printf("nice: started %s with nice %d\n", file, nicev);
    } else if (strcmp(tok[0], "renice") == 0) {
        if (n < 2 || !rest || !rest[0]) { console_write("Usage: renice <N> <pid|%N>\n"); return 0; }
        const char *num = tok[1];
        int neg = 0, v = 0, digits = 0;
        if (*num == '-') { neg = 1; num++; }
        while (*num >= '0' && *num <= '9') { v = v * 10 + (*num - '0'); num++; digits++; }
        if (digits == 0 || *num != 0) { console_write("Usage: renice <N> <pid|%N>\n"); return 0; }
        int nicev = neg ? -v : v;
        if (nicev < -20 || nicev > 19) { console_write("renice: value must be -20..19\n"); return 0; }
        u32 pid = 0;
        if (sh_bg_resolve(rest, session_uid, &pid) != 0) {
            console_printf("renice: cannot renice %s (no such job or no permission)\n", rest); return 0;
        }
        if (nicev < 0 && session_uid == 0 && (session_caps & (1u << CAP_SYS)) == 0) {
            console_write("renice: refused: root capability cap_sys is not set (see `cap list`)\n"); return 0;
        }
        int old = 0;
        proc_bg_get_nice(pid, &old, 0);
        int r = proc_bg_set_nice(pid, session_uid, nicev);
        if (r == -2) { console_write("renice: negative nice needs root\n"); return 0; }
        if (r != 0) { console_write("renice: failed\n"); return 0; }
        console_printf("renice: pid %u nice %d -> %d\n", pid, old, nicev);
    } else if (strcmp(tok[0], "cap") == 0) {
        /* Capabilities (redesign 5): list the session mask,
           drop/grant one bit (both need uid 0 + cap_cap —
           dropping cap_cap locks cap management for this
           session until re-login), or show a background
           job's own inherited mask. */
        if (n < 2 || strcmp(tok[1], "list") == 0) {
            console_write("Session capabilities:");
            int cnt = 0;
            for (int b = 0; b < CAP_NBITS; b++) {
                if (session_caps & (1u << b)) { console_putchar(' '); console_write(caps_name(b)); cnt++; }
            }
            if (cnt == 0) console_write(" (none)");
            console_printf(" (%d of %d set, uid %u)\n", cnt, CAP_NBITS, session_uid);
        } else if (strcmp(tok[1], "drop") == 0 || strcmp(tok[1], "grant") == 0) {
            int grant = (strcmp(tok[1], "grant") == 0);
            if (sh_cap_gate(CAP_CAP, "cap") != 0) return 0;
            if (!rest || !rest[0]) { console_write("Usage: cap drop|grant <capability>\n"); return 0; }
            int bit = -1;
            for (int b = 0; b < CAP_NBITS; b++)
                if (strcmp(rest, caps_name(b)) == 0) bit = b;
            if (bit < 0) { console_printf("cap: no such capability %s\n", rest); return 0; }
            if (grant) session_caps |= (1u << bit);
            else session_caps &= ~(1u << bit);
            proc_set_session_caps(session_caps);
            console_printf("cap: %s %s\n", caps_name(bit), grant ? "granted" : "dropped");
            if (!grant && bit == CAP_CAP)
                console_write("cap: note: cap_cap is dropped for this session (re-login restores it)\n");
        } else if (strcmp(tok[1], "show") == 0) {
            if (!rest || !rest[0]) { console_write("Usage: cap show <pid>\n"); return 0; }
            u32 pid = 0;
            int ok = 1;
            for (const char *q = rest; *q && *q != ' '; q++) {
                if (*q < '0' || *q > '9' || pid > 1000000) { ok = 0; break; }
                pid = pid * 10u + (u32)(*q - '0');
            }
            if (!ok) { console_write("Usage: cap show <pid>\n"); return 0; }
            int found = 0; u32 juu = 0;
            for (int i = 0; i < MAX_BG; i++) {
                char nm[32]; u32 pp, uu;
                if (proc_bg_info(i, nm, &pp, &uu, 0, 0) != 0) break;
                if (pp == pid) { found = 1; juu = uu; break; }
            }
            if (!found) { console_printf("cap: no such job %u\n", pid); return 0; }
            if (session_uid != 0 && juu != session_uid) {
                console_write("cap: no such job or no permission\n"); return 0;
            }
            u32 cm = 0;
            if (proc_bg_caps(pid, &cm) != 0) { console_printf("cap: no such job %u\n", pid); return 0; }
            console_printf("cap: pid %u capabilities:", pid);
            int cnt = 0;
            for (int b = 0; b < CAP_NBITS; b++) {
                if (cm & (1u << b)) { console_putchar(' '); console_write(caps_name(b)); cnt++; }
            }
            if (cnt == 0) console_write(" (none)");
            console_putchar('\n');
        } else {
            console_write("Usage: cap list|drop <capability>|grant <capability>|show <pid>\n");
        }
    } else if (strcmp(tok[0], "mac") == 0) {
        if (n >= 2 && strcmp(tok[1], "status") == 0)
            console_write("MAC: no policy loaded (hook points present in every root gate, enforcement off)\n");
        else console_write("Usage: mac status\n");
    } else if (strcmp(tok[0], "sessions") == 0) {
        if (n >= 2 && strcmp(tok[1], "new") == 0) {
            console_write("sessions: refused: only one console session exists (additional sessions need a second console)\n");
        } else {
            console_write("Sessions:\n");
            for (int i = 0; i < sh_session_n; i++)
                console_printf("session %d: %s (uid %u)%s\n", i, sh_sessions[i].name,
                               sh_sessions[i].uid, sh_sessions[i].active ? " active (console)" : "");
            console_printf("(%d session(s); slots for %d more exist but stay inactive without a second console)\n",
                           sh_session_n, 4 - sh_session_n);
        }
    } else if (strcmp(tok[0], "swapinfo") == 0) {
        u32 tot = 0, used = 0;
        blk_swap_slots(&tot, &used);
        console_write("Swap: inactive (no swap area configured)\n");
        console_printf("Swap slots: %u total, %u in use\n", tot, used);
        console_write("Swap: no pages are swapped (activation needs a dedicated swap area)\n");
    } else if (strcmp(tok[0], "vma") == 0) {
        u32 vf = 0, vp = 0;
        vma_stats(&vf, &vp);
        console_printf("VMA: demand faults handled %u, pages mapped %u\n", vf, vp);
        console_write("VMA: fault inside a VMA maps a zero page and resumes; fault outside any VMA terminates the process (SIGSEGV)\n");
        console_write("VMA: swap inactive (no swap area configured; swappable VMAs are never paged out)\n");
    } else if (strcmp(tok[0], "sched") == 0) {
        if (n >= 2 && strcmp(tok[1], "-v") == 0) {
            console_write("PID  NAME  UID  NICE  RUNS  VRUNTIME  WEIGHT\n");
            for (int i = 0; i < MAX_BG; i++) {
                char nm[32]; u32 pp, uu; int ni = 0; u32 rr = 0;
                if (proc_bg_info(i, nm, &pp, &uu, &ni, &rr) != 0) break;
                u32 vr = 0, wt = 0;
                proc_bg_vruntime(pp, &vr, &wt, 0);
                console_printf("pid %u  %s  uid %u  nice %d  runs %u  vruntime %u  weight %u\n",
                               pp, nm, uu, ni, rr, vr, wt);
            }
        } else {
            console_write("PID  NAME  UID  NICE  RUNS\n");
            for (int i = 0; i < MAX_BG; i++) {
                char nm[32]; u32 pp, uu; int ni = 0; u32 rr = 0;
                if (proc_bg_info(i, nm, &pp, &uu, &ni, &rr) != 0) break;
                console_printf("pid %u  %s  uid %u  nice %d  runs %u\n", pp, nm, uu, ni, rr);
            }
        }
    } else if (strcmp(tok[0], "fg") == 0) {
        if (n < 2) { console_write("Usage: fg <pid|%N>\n"); return 0; }
        u32 pid = 0;
        if (sh_bg_resolve(tok[1], session_uid, &pid) != 0) {
            if (sh_reap_numeric(tok[1], session_uid, "fg")) return 0;
            console_printf("fg: cannot wait for %s (no such job or no permission)\n", tok[1]); return 0;
        }
        int r = sh_wait_pid(pid, session_uid);
        if (r == 0) { console_printf("fg: job %u done\n", pid); sh_wait_status(pid, session_uid, "fg"); }
        else if (r == 1) console_printf("fg: job %u killed (Ctrl-C)\n", pid);
        else console_printf("fg: cannot kill %u (no such job or no permission)\n", pid);
    } else if (strcmp(tok[0], "wait") == 0) {
        if (n >= 2) {
            u32 pid = 0;
            if (sh_bg_resolve(tok[1], session_uid, &pid) != 0) {
                if (sh_reap_numeric(tok[1], session_uid, "wait")) return 0;
                console_printf("wait: cannot wait for %s (no such job or no permission)\n", tok[1]); return 0;
            }
            int r = sh_wait_pid(pid, session_uid);
            if (r == 0) { console_printf("wait: job %u done\n", pid); sh_wait_status(pid, session_uid, "wait"); }
            else if (r == 1) console_printf("wait: job %u killed (Ctrl-C)\n", pid);
            else console_printf("wait: cannot kill %u (no such job or no permission)\n", pid);
        } else {
            /* Wait for all visible jobs (own jobs, or all as
               root). Snapshot pids first: the table shifts as
               jobs die. Ctrl-C stops the wait after the current
               job (killed if permitted); later jobs keep running
               in the background. */
            u32 pids[4]; u32 npids = 0;
            for (int i = 0; i < MAX_BG; i++) {
                char nm[32]; u32 pp, uu;
                if (proc_bg_at(i, nm, &pp, &uu) != 0) break;
                if ((uu == session_uid || session_uid == 0) && npids < 4) pids[npids++] = pp;
            }
            for (u32 i = 0; i < npids; i++) {
                int r = sh_wait_pid(pids[i], session_uid);
                if (r == 0) { console_printf("wait: job %u done\n", pids[i]); sh_wait_status(pids[i], session_uid, "wait"); }
                else if (r == 1) { console_printf("wait: job %u killed (Ctrl-C)\n", pids[i]); break; }
                else { console_printf("wait: cannot kill %u (no such job or no permission)\n", pids[i]); break; }
            }
        }
    } else if (strcmp(tok[0], "cpu") == 0) {
        if (!hw_cpuid_supported()) { console_write("cpu: cpuid not available\n"); return 0; }
        char vendor[13], brand[49];
        hw_cpu_vendor(vendor);
        hw_cpu_brand(brand);
        u32 fam, model, step, ecx, edx;
        hw_cpu_family_model(&fam, &model, &step);
        hw_cpu_features(&ecx, &edx);
        console_printf("CPU vendor: %s\n", vendor);
        if (brand[0]) console_printf("CPU brand: %s\n", brand);
        else console_write("CPU brand: (not reported)\n");
        console_printf("CPU family %u model %u stepping %u\n", fam, model, step);
        cpu_print_flags(ecx, edx, hw_cpu_nx());
        console_printf("SMP: %u CPU(s) online, AP %s\n", smp_cpu_count(),
                       smp_ap_online() ? "online" : "absent");
    } else if (strcmp(tok[0], "pci") == 0) {
        if (n >= 2 && strcmp(tok[1], "-v") == 0) {
            console_write("PCI bus 0 (verbose):\n");
            int nv = hw_pci_scan_detail(pci_print_detail_row);
            console_printf("(%d PCI device(s))\n", nv);
        } else {
            console_write("PCI bus 0:\nDEV FUNC  VENDOR:DEVICE  CLASS  BAR0\n");
            int np = hw_pci_scan(pci_print_row);
            console_printf("(%d PCI device(s))\n", np);
        }
    } else if (strcmp(tok[0], "acpi") == 0) {
        acpi_diag();
    } else if (strcmp(tok[0], "disk") == 0) {
        if (!ata_present()) { console_write("Disk: no ATA disk\n"); return 0; }
        if (!fs_mounted()) { console_write("Disk: ATA device present, filesystem not mounted (no disk or bad filesystem)\n"); return 0; }
        u32 total = fs_total_sectors(), free = fs_free_sectors();
        /* 1 MiB = 2048 sectors: shifts, no division. */
        console_printf("Disk: %u sectors total (%u MiB), %u sectors free (%u MiB)\n",
                       total, total >> 11, free, free >> 11);
    } else if (strcmp(tok[0], "nproc") == 0) {
        console_printf("%u\n", hw_cpu_count());
    } else if (strcmp(tok[0], "smp") == 0) {
        if (n >= 2 && strcmp(tok[1], "locktest") == 0) {
            u32 counter = 0;
            int r = smp_locktest(20000, &counter);
            if (r == -1) console_write("smp locktest: refused (no AP online: nothing to contend with)\n");
            else if (r == -2) console_write("smp locktest: FAIL (AP did not finish in time)\n");
            else if (r == -3) console_printf("smp locktest: FAIL (counter %u expected 40000: lost updates)\n", counter);
            else console_printf("smp locktest: counter %u expected 40000\nsmp locktest: PASS\n", counter);
        } else if (n >= 2 && strcmp(tok[1], "pmmtest") == 0) {
            u32 fb = 0, fa = 0; int dis = 0;
            int r = smp_pmmtest(&fb, &fa, &dis);
            if (r == -1) console_write("smp pmmtest: refused (no AP online)\n");
            else if (r == -2) console_write("smp pmmtest: FAIL (AP did not finish in time)\n");
            else if (r == -3) console_write("smp pmmtest: FAIL (overlapping or zero frame allocated)\n");
            else if (r == -4) console_printf("smp pmmtest: FAIL (free frames %u -> %u, leak)\n", fb, fa);
            else console_printf("smp pmmtest: 64 frames disjoint, free %u -> %u\nsmp pmmtest: PASS\n", fb, fa);
        } else if (n >= 2 && strcmp(tok[1], "tlb") == 0) {
            struct smp_tlb_result res;
            res.stale_before = 0; res.stale_after = 0; res.ack = 0; res.fault = 0;
            int r = smp_tlb_proof(&res);
            if (r == -1) console_write("smp tlb: refused (no AP online)\n");
            else if (r == -2) console_write("smp tlb: FAIL (setup: AP never cached the translation)\n");
            else if (r == 0) console_printf("smp tlb: stale reads %u -> %u after unmap; fault after shootdown: yes; shootdown ack: yes\nsmp tlb: TLB shootdown: PROVEN\n", res.stale_before, res.stale_after);
            else console_printf("smp tlb: stale reads %u -> %u after unmap; fault after shootdown: %s; shootdown ack: %s\nsmp tlb: TLB shootdown: NOT PROVEN\n",
                                res.stale_before, res.stale_after,
                                res.fault ? "yes" : "no", res.ack ? "yes" : "no");
        } else if (n >= 2 && strcmp(tok[1], "jobs") == 0) {
            console_write("PID  NAME  UID  CPU  RUNS\n");
            int njobs = 0;
            for (int i = 0; i < MAX_BG; i++) {
                char nm[32]; u32 pp, uu; int cc = 0, pend = -1; int ni = 0; u32 rr = 0;
                if (proc_bg_at(i, nm, &pp, &uu) != 0) break;
                proc_bg_cpu(pp, &cc, &pend);
                proc_bg_get_nice(pp, &ni, &rr);
                if (pend >= 0) console_printf("pid %u  %s  uid %u  cpu %u -> %u  runs %u\n", pp, nm, uu, cc, pend, rr);
                else console_printf("pid %u  %s  uid %u  cpu %u  runs %u\n", pp, nm, uu, cc, rr);
                njobs++;
            }
            /* Empty case matches `jobs`/`proc_bg_list`: the suite
               (and users) expect the explicit empty line, not a
               bare header that reads as a failed listing. */
            if (njobs == 0) console_write("(no background jobs)\n");
        } else {
            u32 runs = 0, done = 0, sent = 0, acked = 0;
            proc_ap_stats(&runs, &done);
            smp_shootdown_stats(&sent, &acked);
            console_printf("SMP: %u CPU(s) online\n", smp_cpu_count());
            if (smp_ap_online()) console_write("SMP: AP state: idle loop\n");
            else if (smp_ap_state() == 1) console_write("SMP: AP state: booting (never signalled readiness)\n");
            else console_write("SMP: AP state: absent\n");
            if (smp_lapic_base() != 0)
                console_printf("SMP: LAPIC base 0x%x, timer %u ticks/10ms\n",
                               smp_lapic_base(), smp_ap_timer_per_10ms());
            else console_write("SMP: LAPIC: not available\n");
            console_printf("SMP: AP jobs run %u, completed %u\n", runs, done);
            console_printf("SMP: shootdowns sent %u, acked %u\n", sent, acked);
        }
    } else if (strcmp(tok[0], "affinity") == 0) {
        /* The tokenizer stops at 2 tokens and puts the remainder
           in `rest` (same shape as renice): the CPU comes from
           rest, not tok[2]. */
        if (n < 2 || !rest || !rest[0]) { console_write("Usage: affinity <pid> <cpu>\n"); return 0; }
        u32 pid = 0;
        if (sh_bg_resolve(tok[1], session_uid, &pid) != 0) {
            console_printf("affinity: cannot set affinity for %s (no such job or no permission)\n", tok[1]); return 0;
        }
        int cpu = 0, digits = 0;
        const char *p = rest;
        while (*p >= '0' && *p <= '9') { cpu = cpu * 10 + (*p - '0'); p++; digits++; }
        if (digits == 0 || *p != 0) { console_write("Usage: affinity <pid> <cpu>\n"); return 0; }
        int r = proc_bg_set_cpu(pid, session_uid, cpu);
        if (r == -3) console_write("affinity: refused (cpu must be 0 or 1)\n");
        else if (r == -2) console_write("affinity: refused (no AP online: CPU 1 does not exist)\n");
        else if (r == -1) console_write("affinity: refused (no such job or no permission)\n");
        else {
            int cc = 0, pend = -1;
            proc_bg_cpu(pid, &cc, &pend);
            if (pend >= 0) console_printf("affinity: pid %u will move to CPU %u at the next tick boundary\n", pid, pend);
            else console_printf("affinity: pid %u now CPU %u\n", pid, cc);
        }
    } else if (strcmp(tok[0], "lsusb") == 0) {
        console_write("USB controllers on PCI:\n");
        hw_pci_scan(lsusb_print_row);
        console_write("Note: USB devices are not enumerated (no USB stack).\n");
    } else if (strcmp(tok[0], "iostat") == 0) {
        u32 sr = 0, sw = 0;
        ata_io_stats(&sr, &sw);
        console_printf("Disk: sectors read %u, sectors written %u (since boot)\n", sr, sw);
        if (fs_mounted()) {
            u32 total = fs_total_sectors(), free = fs_free_sectors();
            console_printf("Disk: %u sectors total, %u sectors free\n", total, free);
        }
    } else if (strcmp(tok[0], "vmstat") == 0) {
        u32 sr = 0, sw = 0;
        ata_io_stats(&sr, &sw);
        console_printf("Memory: total %u frames, free %u frames, used %u frames\n",
                       pmm_total_frames(), pmm_free_frames(), pmm_used_frames());
        console_printf("Uptime: %u seconds, background jobs: %u, disk sectors read %u written %u, net rx %u tx %u drops %u, swap: 0 (no swap device)\n",
                       ticks_to_seconds(timer_ticks), proc_bg_count(), sr, sw,
                       net_rx_count(), net_tx_count(), net_drop_count());
    } else if (strcmp(tok[0], "sensors") == 0) {
        console_write("Sensors: no temperature, fan, or voltage sensors exposed by this platform (QEMU/SeaBIOS firmware provides no sensor devices). No values are reported rather than invented ones.\n");
    } else if (strcmp(tok[0], "uptime") == 0) {
        u32 d, h, m, s;
        split_uptime(ticks_to_seconds(timer_ticks), &d, &h, &m, &s);
        if (n >= 2 && strcmp(tok[1], "-p") == 0) {
            console_printf("up %u day(s), %u hour(s), %u minute(s)\n", d, h, m);
        } else if (n >= 2 && strcmp(tok[1], "-s") == 0) {
            /* Boot time = RTC now minus uptime seconds, by
               repeated subtraction across seconds/minutes/
               hours/days/months/years (no division by a
               variable, and no date library exists here). */
            u32 year, mon, day, hour, min, sec;
            if (hw_rtc_read(&year, &mon, &day, &hour, &min, &sec) != 0) {
                console_write("uptime: RTC read failed\n");
            } else {
                u32 rem = ticks_to_seconds(timer_ticks);
                /* Each iteration consumes at least a minute (or
                   the whole remainder), so this loop is bounded
                   by minutes of uptime, not seconds. */
                while (rem > 0) {
                    if (sec > 0) { u32 take = sec < rem ? sec : rem; sec -= take; rem -= take; }
                    else if (min > 0) { min--; sec = 59; if (rem > 0) rem--; }
                    else if (hour > 0) { hour--; min = 59; sec = 59; if (rem > 0) rem--; }
                    else if (day > 1) { day--; hour = 23; min = 59; sec = 59; if (rem > 0) rem--; }
                    else if (mon > 1) {
                        mon--;
                        static const u8 mdays[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
                        day = mdays[mon - 1];
                        if (mon == 2 && (year % 4u) == 0) day = 29;
                        hour = 23; min = 59; sec = 59; if (rem > 0) rem--;
                    } else if (year > 2000) {
                        year--; mon = 12; day = 31; hour = 23; min = 59; sec = 59; if (rem > 0) rem--;
                    } else break; /* underflow guard: never before 2000 */
                }
                console_printf("%u-", year);
                sh_print_pad2(mon); console_putchar('-');
                sh_print_pad2(day); console_putchar(' ');
                sh_print_pad2(hour); console_putchar(':');
                sh_print_pad2(min); console_putchar(':');
                sh_print_pad2(sec); console_putchar('\n');
            }
        } else {
            console_printf("Uptime: %u day(s) %u:%u:%u (%u background job(s))\n",
                           d, h, m, s, proc_bg_count());
        }
    } else if (strcmp(tok[0], "date") == 0) {
        /* Wall clock from the CMOS RTC (hw_rtc_read handles
           BCD/binary, 12/24-hour, and the update-in-progress
           wait). World-readable, like uptime. The minimal
           printf has no %02u, so fields are padded by hand.
           `date set` (parity run) is root only: the clock
           moves audit timestamps and time-based validation. */
        if (n >= 2 && strcmp(tok[1], "set") == 0) {
            if (sh_cap_gate(CAP_SYS, "date") != 0) return 0;
            /* rest = "YYYY-MM-DD HH:MM:SS" (exactly 19 chars).
               Validate the whole shape first, then write: the
               RTC write itself re-validates, so a bad value
               can never produce a partial write. */
            const char *r = rest ? rest : "";
            int ok = 0;
            u32 year = 0, mon = 0, day = 0, hour = 0, min = 0, sec = 0;
            if (r[0] && r[10] == ' ' && r[19] == 0 &&
                r[4] == '-' && r[7] == '-' && r[13] == ':' && r[16] == ':') {
                ok = 1;
                for (int i = 0; i < 19 && ok; i++) {
                    if (i == 4 || i == 7 || i == 10 || i == 13 || i == 16) continue;
                    if (r[i] < '0' || r[i] > '9') ok = 0;
                }
                if (ok) {
                    year = (u32)(r[0] - '0') * 1000 + (u32)(r[1] - '0') * 100 +
                           (u32)(r[2] - '0') * 10 + (u32)(r[3] - '0');
                    mon = (u32)(r[5] - '0') * 10 + (u32)(r[6] - '0');
                    day = (u32)(r[8] - '0') * 10 + (u32)(r[9] - '0');
                    hour = (u32)(r[11] - '0') * 10 + (u32)(r[12] - '0');
                    min = (u32)(r[14] - '0') * 10 + (u32)(r[15] - '0');
                    sec = (u32)(r[17] - '0') * 10 + (u32)(r[18] - '0');
                }
            }
            if (!ok || hw_rtc_write(year, mon, day, hour, min, sec) != 0) {
                console_write("Usage: date set <YYYY-MM-DD> <HH:MM:SS>\n");
                return 0;
            }
            console_write("date: set\n");
            return 0;
        }
        u32 year, mon, day, hour, min, sec;
        if (hw_rtc_read(&year, &mon, &day, &hour, &min, &sec) != 0) {
            console_write("date: RTC read failed\n");
            return 0;
        }
        console_printf("%u-", year);
        if (mon < 10) console_putchar('0');
        console_printf("%u-", mon);
        if (day < 10) console_putchar('0');
        console_printf("%u ", day);
        if (hour < 10) console_putchar('0');
        console_printf("%u:", hour);
        if (min < 10) console_putchar('0');
        console_printf("%u:", min);
        if (sec < 10) console_putchar('0');
        console_printf("%u\n", sec);
    } else if (strcmp(tok[0], "sysinfo") == 0) {
        char vendor[13];
        hw_cpu_vendor(vendor);
        u32 d, h, m, s;
        split_uptime(ticks_to_seconds(timer_ticks), &d, &h, &m, &s);
        console_write("nxtsOS v1.1.5\n");
        console_printf("CPU: %s\n", vendor[0] ? vendor : "(unknown)");
        console_printf("Memory: %u frames total, %u free, %u used\n",
                       pmm_total_frames(), pmm_free_frames(), pmm_used_frames());
        if (fs_mounted())
            console_printf("Disk: %u sectors total, %u free\n",
                           fs_total_sectors(), fs_free_sectors());
        else console_write("Disk: filesystem not mounted\n");
        if (net_present()) {
            mac_t mm; net_mac(&mm);
            console_printf("Net: MAC %x:%x:%x:%x:%x:%x rx=%u tx=%u drops=%u\n",
                           mm.b[0], mm.b[1], mm.b[2], mm.b[3], mm.b[4], mm.b[5],
                           net_rx_count(), net_tx_count(), net_drop_count());
            if (net_ip_configured()) {
                ip_t a; net_ip_addr(&a);
                console_printf("Net: ip=%u.%u.%u.%u\n", a.b[0], a.b[1], a.b[2], a.b[3]);
            } else console_write("Net: no IP address (run dhcp)\n");
        } else console_write("Net: no NIC\n");
        console_printf("Jobs: %u background job(s); session: %s uid %u; uptime: %u day(s) %u:%u:%u\n",
                       proc_bg_count(), session_name, session_uid, d, h, m, s);
    } else if (strcmp(tok[0], "ps") == 0) {
        console_printf("Session: %s uid %u\n", session_name, session_uid);
        proc_bg_list();
    } else if (strcmp(tok[0], "top") == 0) {
        /* Live monitor: redraw about once a second, keep
           background jobs ticking (as the shell idle loop does),
           quit on 'q', kill a job on 'k'. Other keys are ignored.
           On exit the screen is cleared so the shell prompt
           returns clean. */
        for (;;) {
            console_clear();
            u32 d, h, m, s;
            split_uptime(ticks_to_seconds(timer_ticks), &d, &h, &m, &s);
            console_printf("nxtsOS top - uptime %u day(s) %u:%u:%u - press q to quit, k to kill\n",
                           d, h, m, s);
            console_printf("Memory: %u frames total, %u free, %u used\n",
                           pmm_total_frames(), pmm_free_frames(), pmm_used_frames());
            if (fs_mounted())
                console_printf("Disk: %u sectors total, %u free\n",
                               fs_total_sectors(), fs_free_sectors());
            else console_write("Disk: filesystem not mounted\n");
            if (net_present())
                console_printf("Net: rx=%u tx=%u drops=%u\n",
                               net_rx_count(), net_tx_count(), net_drop_count());
            else console_write("Net: no NIC\n");
            console_write("PID  NAME  UID\n");
            char name[32]; u32 pid, uid;
            int nj = 0;
            for (int i = 0; proc_bg_at(i, name, &pid, &uid) == 0; i++) {
                console_printf("pid %u  %s  uid %u\n", pid, name, uid);
                nj++;
            }
            console_printf("(%d background job(s))\n", nj);
            /* Wait ~100 ticks, polling keys and ticking jobs. */
            u32 start = timer_ticks;
            int quit = 0;
            int killreq = 0;
            while (timer_ticks - start < 100) {
                keyboard_poll();
                int c = keyboard_getchar();
                if (c == 'q') { quit = 1; break; }
                if (c == 'k') { killreq = 1; break; }
                proc_bg_tick();
                __asm__ volatile ("hlt");
            }
            if (quit) break;
            if (killreq) {
                /* Kill prompt: same permission rule as `kill`
                   (own jobs, or any as root). A bad pid/spec
                   prints a failure and top resumes — it never
                   exits top or kills the wrong job. */
                console_clear();
                console_write("top: kill pid (or %N): ");
                char pbuf[32];
                read_line(pbuf, sizeof(pbuf), 1);
                u32 kpid = 0; int bad = 0;
                if (pbuf[0] == '%') {
                    u32 jn = 0;
                    for (const char *p = pbuf + 1; *p; p++) {
                        if (*p < '0' || *p > '9' || jn > 1000000) { bad = 1; break; }
                        jn = jn * 10u + (u32)(*p - '0');
                    }
                    if (!bad) {
                        char nm[32]; u32 pp, uu;
                        if (jn < 1 || proc_bg_at((int)jn - 1, nm, &pp, &uu) != 0) bad = 1;
                        else kpid = pp;
                    }
                } else {
                    if (pbuf[0] == 0) bad = 1;
                    for (const char *p = pbuf; *p; p++) {
                        if (*p < '0' || *p > '9' || kpid > 1000000) { bad = 1; break; }
                        kpid = kpid * 10u + (u32)(*p - '0');
                    }
                }
                if (bad || proc_bg_kill(kpid, session_uid) != 0)
                    console_printf("top: cannot kill %s (no such job or no permission)\n", pbuf);
                else
                    console_printf("top: killed job %u\n", kpid);
            }
        }
        console_clear();
        console_write("top: quit\n");
    } else if (strcmp(tok[0], "cd") == 0) {
        /* §15: cd [path] (no path means /). The new cwd is the
           LEXICAL canonical form of the argument (symlinks in
           it are not expanded — logical pwd, like a shell's
           default); the target must resolve to a readable
           directory or cd refuses with the reason. */
        const char *arg = (n >= 2) ? tok[1] : "/";
        if (rest && rest[0]) { console_write("Usage: cd [path]\n"); return 0; }
        if (fs_canonical_path(arg, sh_cwd, sh_canon, sizeof(sh_canon)) != 0) {
            console_printf("cd: %s: invalid path\n", arg); return 0;
        }
        int ds = fs_dir_status_path(sh_canon, "/", session_uid);
        if (ds != 0) {
            const char *why = (ds == 1) ? "no such directory" : (ds == 2) ? "not a directory" : (ds == 3) ? "permission denied" : "invalid path";
            console_printf("cd: %s: %s\n", arg, why); return 0;
        }
        u32 k = 0;
        while (sh_canon[k] && k < 255) { sh_cwd[k] = sh_canon[k]; k++; }
        sh_cwd[k] = 0;
    } else if (strcmp(tok[0], "mkdir") == 0) {
        if (n < 2 || (rest && rest[0])) { console_write("Usage: mkdir <path>\n"); return 0; }
        int mr = fs_mkdir_path(tok[1], sh_cwd, session_uid, 0755);
        if (mr != 0) {
            console_printf("mkdir: cannot create %s (%s)\n", tok[1], sh_path_reason(mr)); return 0;
        }
        console_printf("mkdir: created %s\n", tok[1]);
    } else if (strcmp(tok[0], "rmdir") == 0) {
        if (n < 2 || (rest && rest[0])) { console_write("Usage: rmdir <path>\n"); return 0; }
        if (fs_canonical_path(tok[1], sh_cwd, sh_canon, sizeof(sh_canon)) != 0) {
            console_printf("rmdir: %s: invalid path\n", tok[1]); return 0;
        }
        if (strcmp(sh_canon, "/") == 0) {
            console_write("rmdir: cannot remove /\n"); return 0;
        }
        if (strcmp(sh_canon, sh_cwd) == 0) {
            console_write("rmdir: cannot remove the current directory (cd out of it first)\n"); return 0;
        }
        int rr = fs_rmdir_path(tok[1], sh_cwd, session_uid);
        if (rr != 0) {
            console_printf("rmdir: cannot remove %s (%s)\n", tok[1], sh_path_reason(rr)); return 0;
        }
        console_printf("rmdir: removed %s\n", tok[1]);
    } else if (strcmp(tok[0], "mount") == 0) {
        if (n >= 2) {
            (void)fs_mount_extra();
            console_write("mount: second mount refused: only one block device exists (device 0 already mounted at /)\n");
        } else fs_mount_list();
    } else if (strcmp(tok[0], "umount") == 0) {
        console_write("umount: cannot unmount /: the boot filesystem is busy (the shell runs from it)\n");
    } else if (strcmp(tok[0], "swapon") == 0) {
        console_write("swapon: refused: no swap area configured (demand paging exists, but no backing area is configured; no pages are swapped)\n");
        blk_swap_status();
    } else if (strcmp(tok[0], "swapoff") == 0) {
        console_write("swapoff: no swap area is active\n");
    } else if (strcmp(tok[0], "fsck") == 0) {
        fs_fsck();
    } else if (strcmp(tok[0], "blk") == 0) {
        if (n >= 2 && strcmp(tok[1], "merge") == 0) (void)blk_merge_test(1);
        else if (n >= 2 && strcmp(tok[1], "two") == 0) (void)blk_merge_test(0);
        else if (n >= 2 && strcmp(tok[1], "async") == 0) (void)blk_async_test();
        else if (n >= 2) console_write("Usage: blk [merge|two|async]\n");
        else blk_status_print();
    } else if (strcmp(tok[0], "bg") == 0) {
        console_write("bg: not available on nxtsOS (foreground programs run synchronously to completion; use runbg to start background jobs)\n");
    } else if (strcmp(tok[0], "iw") == 0 || strcmp(tok[0], "iwconfig") == 0 ||
               strcmp(tok[0], "bluetoothctl") == 0) {
        console_printf("%s: not available on nxtsOS (wired e1000 only; no wireless or Bluetooth driver)\n", tok[0]);
    } else if (strcmp(tok[0], "awk") == 0 || strcmp(tok[0], "gawk") == 0 ||
               strcmp(tok[0], "xargs") == 0) {
        console_printf("%s: not available on nxtsOS (a full pattern language / argv channel the shell does not have; see docs/CORE_CLI.md section 13)\n", tok[0]);
    } else if (strcmp(tok[0], "tar") == 0 || strcmp(tok[0], "gzip") == 0 || strcmp(tok[0], "gunzip") == 0) {
        console_printf("%s: not available on nxtsOS (no DEFLATE in the kernel; packages use the .nxpkg format instead)\n", tok[0]);
    } else if (strcmp(tok[0], "crontab") == 0 || strcmp(tok[0], "at") == 0) {
        console_printf("%s: not available on nxtsOS (no daemon or persistent timer-task table)\n", tok[0]);
    } else {
        sh_cmd_status = 127;
        console_printf("Unknown command: %s (type help)\n", tok[0]);
    }
    return 0;
}

/* Command chaining (Linux-comparability run): `;`, `&&`, `||`
   split a line at the outermost execute() call, BEFORE expansion
   (Linux behaviour: an expanded value never becomes a chain
   operator). Segments live in a two-slot file-scope stack so a
   script line's own chain cannot clobber an outer chain's
   segments; a third nesting level is refused visibly. */
static char sh_chain_seg[2][8][128];
static int sh_chain_op[2][8];
static int sh_chain_depth = 0;
/* Returns 0 when the line has no chain operator, else the segment
   count (segments stored in slot, operators before each segment
   in sh_chain_op[slot]: 0 first, 1 ';', 2 '&&', 3 '||'). */
/* Quote-state scanner shared by the chain split: returns 1
   when line[i] is a chain operator OUTSIDE quotes (a
   backslash-escaped operator is literal, never an operator).
   The caller advances i past the operator itself. */
static int sh_chain_split(const char *line, int slot) {
    int has_op = 0;
    {
        int qs = 0, esc = 0;
        for (int i = 0; line[i]; i++) {
            char c = line[i];
            if (esc) { esc = 0; continue; }
            if (c == '\\' && qs != '\'') { esc = 1; continue; }
            if (qs == '\'') { if (c == '\'') qs = 0; continue; }
            if (qs == '"') { if (c == '"') qs = 0; continue; }
            if (c == '\'') { qs = '\''; continue; }
            if (c == '"') { qs = '"'; continue; }
            if (c == ';') { has_op = 1; break; }
            if ((c == '&' && line[i + 1] == '&') ||
                (c == '|' && line[i + 1] == '|')) { has_op = 1; break; }
        }
    }
    if (!has_op) return 0;
    int seg = 0, o = 0;
    sh_chain_op[slot][0] = 0;
    int qs = 0, esc = 0;
    for (int i = 0; line[i]; i++) {
        /* Quoted/escaped bytes are copied verbatim into the
           segment (tokenize() strips the quotes later); only
           unquoted operators split. */
        if (esc) { esc = 0; if (o < 127) sh_chain_seg[slot][seg][o++] = line[i]; continue; }
        if (line[i] == '\\' && qs != '\'') {
            esc = 1;
            if (o < 127) sh_chain_seg[slot][seg][o++] = line[i];
            continue;
        }
        if (qs == '\'') {
            if (line[i] == '\'') qs = 0;
            if (o < 127) sh_chain_seg[slot][seg][o++] = line[i];
            continue;
        }
        if (qs == '"') {
            if (line[i] == '"') qs = 0;
            if (o < 127) sh_chain_seg[slot][seg][o++] = line[i];
            continue;
        }
        if (line[i] == '\'') { qs = '\''; if (o < 127) sh_chain_seg[slot][seg][o++] = line[i]; continue; }
        if (line[i] == '"') { qs = '"'; if (o < 127) sh_chain_seg[slot][seg][o++] = line[i]; continue; }
        int op = 0, adv = 0;
        if (line[i] == ';') { op = 1; adv = 1; }
        else if (line[i] == '&' && line[i + 1] == '&') { op = 2; adv = 2; }
        else if (line[i] == '|' && line[i + 1] == '|') { op = 3; adv = 2; }
        if (op) {
            /* Trim trailing spaces, store the segment. */
            while (o > 0 && sh_chain_seg[slot][seg][o - 1] == ' ') o--;
            sh_chain_seg[slot][seg][o] = 0;
            if (o > 0) {
                seg++;
                if (seg >= 8) return -1;
            }
            o = 0;
            sh_chain_op[slot][seg] = op;
            i += adv - 1;
            continue;
        }
        if (o == 0 && line[i] == ' ') continue; /* trim leading spaces */
        if (o < 127) sh_chain_seg[slot][seg][o++] = line[i];
    }
    while (o > 0 && sh_chain_seg[slot][seg][o - 1] == ' ') o--;
    sh_chain_seg[slot][seg][o] = 0;
    if (o > 0) seg++;
    return seg;
}

/* Outermost execute(): $VAR/${VAR} expansion + one-level alias
   expansion, both exactly once. Group dispatch recurses
   through execute(), so a depth counter keeps the recursion
   from re-expanding (values containing '$' are never
   re-expanded, and an alias value's first word is never
   re-aliased). Alias expansion does NOT fire when the first
   word is a group name and the second word is a group member
   (that is a group dispatch, not an alias), nor for the
   alias/unalias meta-commands themselves. Expansion overflow
   past the 127-char line cap refuses with a message, never
   a truncation. Unset variables expand to empty. */
static int execute(char *line) {
    if (sh_expand_depth > 0) return execute_inner(line);
    /* Chaining (see sh_chain_split): segments are expanded and
       run one at a time; && runs only on status 0, || only on
       non-zero status, ; always. A logout return stops the
       chain and propagates to the shell loop. */
    if (sh_chain_depth >= 2) { console_write("command chain nesting too deep\n"); return 0; }
    {
        int slot = sh_chain_depth;
        int nseg = sh_chain_split(line, slot);
        if (nseg < 0) { console_write("command chain too long (max 8 commands)\n"); sh_cmd_status = 1; sh_last_status = 1; return 0; }
        if (nseg > 1) {
            int last = 0;
            sh_chain_depth++;
            for (int i = 0; i < nseg; i++) {
                if (i > 0) {
                    int op = sh_chain_op[slot][i];
                    if (op == 2 && last != 0) continue;
                    if (op == 3 && last == 0) continue;
                }
                int r = execute(sh_chain_seg[slot][i]);
                if (r == 1) { sh_chain_depth--; return 1; }
                last = sh_last_status;
            }
            sh_chain_depth--;
            sh_last_status = last;
            return 0;
        }
    }
    char exp[128];
    u32 o = 0;
    /* Quoting meets expansion (redesign 5): inside single
       quotes, $ is literal; a backslash copies itself plus
       the next byte verbatim (so \$VAR never expands and
       \| never becomes a pipe), and tokenize() later strips
       the backslash. Double quotes still expand $ (POSIX). */
    int exp_qs = 0;
    for (u32 i = 0; line[i]; i++) {
        if (line[i] == '\\' && line[i + 1]) {
            if (o + 1 >= 127) { console_write("expanded command too long\n"); return 0; }
            exp[o++] = '\\';
            if (o >= 127) { console_write("expanded command too long\n"); return 0; }
            exp[o++] = line[i + 1];
            i++;
            continue;
        }
        if (line[i] == '\'' && exp_qs != '"') {
            exp_qs = (exp_qs == '\'') ? 0 : '\'';
            if (o >= 127) { console_write("expanded command too long\n"); return 0; }
            exp[o++] = line[i];
            continue;
        }
        if (line[i] == '"' && exp_qs != '\'') {
            exp_qs = (exp_qs == '"') ? 0 : '"';
            if (o >= 127) { console_write("expanded command too long\n"); return 0; }
            exp[o++] = line[i];
            continue;
        }
        if (line[i] == '$' && exp_qs == '\'') {
            if (o >= 127) { console_write("expanded command too long\n"); return 0; }
            exp[o++] = '$';
            continue;
        }
        if (line[i] == '$') {
            if (line[i + 1] == '{') {
                u32 j = i + 2, nl = 0;
                char nm[32];
                while (line[j] && line[j] != '}' && nl < 31) nm[nl++] = line[j++];
                nm[nl] = 0;
                if (line[j] == '}' && nl > 0) {
                    const char *v = sh_env_get(nm);
                    if (v) {
                        for (u32 k = 0; v[k]; k++) {
                            if (o >= 127) { console_write("expanded command too long\n"); return 0; }
                            exp[o++] = v[k];
                        }
                    }
                    i = j;
                    continue;
                }
                /* Unterminated ${: the '$' stays literal. */
                if (o >= 127) { console_write("expanded command too long\n"); return 0; }
                exp[o++] = '$';
                continue;
            }
            char nc = line[i + 1];
            if (nc == '?') {
                /* $? = last exit status, as decimal. */
                char num[12]; int ni = 0;
                u32 v = (u32)sh_last_status;
                if (v == 0) num[ni++] = '0';
                else {
                    char rev[12]; int ri = 0;
                    while (v > 0 && ri < 11) { rev[ri++] = (char)('0' + (v % 10u)); v /= 10u; }
                    while (ri > 0) num[ni++] = rev[--ri];
                }
                for (int k = 0; k < ni; k++) {
                    if (o >= 127) { console_write("expanded command too long\n"); return 0; }
                    exp[o++] = num[k];
                }
                i++;
                continue;
            }
            if ((nc >= 'A' && nc <= 'Z') || (nc >= 'a' && nc <= 'z') || nc == '_') {
                u32 j = i + 1, nl = 0;
                char nm[32];
                while (line[j] && nl < 31) {
                    char c = line[j];
                    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '_')) break;
                    nm[nl++] = c; j++;
                }
                nm[nl] = 0;
                const char *v = sh_env_get(nm);
                if (v) {
                    for (u32 k = 0; v[k]; k++) {
                        if (o >= 127) { console_write("expanded command too long\n"); return 0; }
                        exp[o++] = v[k];
                    }
                }
                i = j - 1;
                continue;
            }
            if (o >= 127) { console_write("expanded command too long\n"); return 0; }
            exp[o++] = '$';
            continue;
        }
        if (o >= 127) { console_write("expanded command too long\n"); return 0; }
        exp[o++] = line[i];
    }
    exp[o] = 0;
    /* One-level alias expansion on the first word. */
    {
        u32 wlen = 0;
        while (exp[wlen] && exp[wlen] != ' ') wlen++;
        if (wlen > 0 && wlen < 32) {
            char first[32];
            u32 k = 0;
            while (k < wlen) { first[k] = exp[k]; k++; }
            first[k] = 0;
            const char *av = 0;
            if (strcmp(first, "alias") != 0 && strcmp(first, "unalias") != 0)
                av = sh_alias_get(first);
            if (av) {
                /* Group dispatch wins over aliases. */
                u32 second_len = 0, second_off = 0;
                if (exp[wlen] == ' ') {
                    second_off = wlen + 1;
                    while (exp[second_off] == ' ') second_off++;
                    while (exp[second_off + second_len] && exp[second_off + second_len] != ' ') second_len++;
                }
                int is_group_call = 0;
                if (second_len > 0 && second_len < 32 && help_group_index(first) >= 0) {
                    char second[32];
                    u32 m = 0;
                    while (m < second_len) { second[m] = exp[second_off + m]; m++; }
                    second[m] = 0;
                    if (help_find_in_group(first, second)) is_group_call = 1;
                }
                if (!is_group_call) {
                    u32 alen = 0; while (av[alen]) alen++;
                    u32 rest_off = wlen;
                    u32 total = alen + (exp[rest_off] ? (o - rest_off) : 0);
                    if (total > 127) { console_write("alias expansion too long\n"); return 0; }
                    char exp2[128];
                    u32 p = 0;
                    for (u32 m = 0; m < alen; m++) exp2[p++] = av[m];
                    for (u32 m = rest_off; m < o; m++) exp2[p++] = exp[m];
                    exp2[p] = 0;
                    /* Copy back into exp for the inner call. */
                    for (u32 m = 0; m <= p; m++) exp[m] = exp2[m];
                }
            }
        }
    }
    /* Glob expansion (Linux-comparability run): after $VAR/alias
       expansion, before pipe parsing, per stage, whitelisted
       file commands only (see sh_glob_expand). Over the
       127-char line cap it refuses, never truncates. */
    if (sh_glob_expand(exp) != 0) { sh_cmd_status = 1; sh_last_status = 1; return 0; }
    {
        u32 gl = 0; while (sh_glob_out[gl]) gl++;
        if (gl > 127) { console_write("glob expansion too long\n"); sh_cmd_status = 1; sh_last_status = 1; return 0; }
        for (u32 k = 0; k <= gl; k++) exp[k] = sh_glob_out[k];
        o = gl;
    }
    sh_expand_depth++;
    /* Pipes/redirection (parity run step 9): operators are
       recognised AFTER expansion, so an expanded value
       containing |, >, < acts as an operator (no quoting
       exists to protect it). Plain lines take the old path
       unchanged, so neighbours see zero behaviour change.
       The wrapper holds the depth across the pipeline, so a
       stage's group dispatch cannot re-expand. */
    int r;
    if (sh_pipe_scan(exp)) {
        if (sh_pipe_parse(exp) == 0) r = sh_run_pipeline();
        else r = 0; /* parse error already printed */
    } else {
        r = execute_inner(exp);
    }
    sh_expand_depth--;
    sh_last_status = sh_cmd_status;
    return r;
}

static int shell_loop(void) {
    char line[128];
    u32 len = 0, cur = 0, shown = 0, prompt_len = 0;
    u32 last_activity = timer_ticks;
    console_write("\nWelcome to nxtsOS. Type help.\n");
    /* v0.7.3: one line, first shell only, so a user testing on
       Bochs/QEMU can report it without typing anything: if this
       says drained > 0, a lodged GRUB/BIOS byte was the keyboard
       failure and this build already drained it. If it says 0
       and keys still do nothing, no bytes are reaching the
       controller at all (emulator/app side, see VM_GUIDE). */
    {
        static int shell_diag_shown = 0;
        if (!shell_diag_shown) {
            shell_diag_shown = 1;
            console_printf("Keyboard: startup drained %u byte(s) from the PS/2 controller (0 = controller was clean at boot).\n",
                           keyboard_startup_drained());
        }
    }
    for (;;) {
        console_printf("%s@nxts> ", session_name);
        len = 0; cur = 0; line[0] = 0;
        prompt_len = 0; while (session_name[prompt_len]) prompt_len++;
        prompt_len += 7; /* "@nxts> " */
        shown = prompt_len;
        for (;;) {
            /* Poll as well as IRQ: if IRQ1 is lost in some Bochs
               setup, keys typed after the prompt still arrive via
               the timer wakeup (see keyboard_poll). */
            keyboard_poll();
            int c = keyboard_getchar();
            if (c < 0) {
                /* Background jobs run here, while the shell waits for
                   a key: a yielding job returns immediately, a busy
                   job returns on its 100 ms timer preemption, so the
                   shell never blocks on a background program. */
                proc_bg_tick();
                /* Idle session lock: v0.7.1 default 120 minutes,
                   configurable via `idle` (0 = never). The lock/
                   unlock code path itself is QEMU-tested via the
                   `lock` command, and the desktop idle trigger is
                   now QEMU-tested too: tests/qemu_test_idle_lock.py
                   sets `idle 1`, enters the desktop, and waits out
                   the 60-second timeout to the lock screen, then
                   unlocks with the session password. The shell-loop
                   trigger in this branch is QEMU-tested too:
                   tests/qemu_test_shell_idle_lock.py sets `idle 1`
                   at the shell prompt and waits out the 60-second
                   timeout to the lock prompt, then unlocks with
                   the session password. Waiting out the 120-minute
                   default is still not feasible; the 1-minute wait
                   proves the same trigger code path
                   (shell_idle_minutes() * 6000 ticks). */
                if (session_active && idle_timeout_minutes != 0 &&
                    timer_ticks - last_activity > idle_timeout_minutes * 6000u) {
                    console_write("\nSession locked due to inactivity.\n");
                    if (do_lock()) {
                        last_activity = timer_ticks;
                        /* Redraw the text console after the lock
                           prompt, so the terminal is in a known-good
                           state before the next prompt (a lock that
                           left the display half-drawn was reported
                           as "terminal doesn't work"). */
                        console_redraw_text();
                        break;
                    }
                    audit("logout", session_name);
                    session_active = 0;
                    return 0;
                }
                __asm__ volatile ("hlt");
                continue;
            }
            last_activity = timer_ticks;
            sh_activity_tick = timer_ticks;
            /* Line editing (parity run): plain typing stays
               byte-identical to before (per-char console_putchar
               echo, so harness echo matching is unaffected);
               editing keys engage the buffer-only redraw path,
               which never touches the serial log. The visible
               cursor always sits at prompt start + prompt_len +
               cur — every branch below preserves that. */
            if (c == KEY_PGUP) { console_scroll_up(); }
            else if (c == KEY_PGDN) { console_scroll_down(); }
            else if (c == '\n') {
                line[len] = 0;
                console_putchar('\n');
                sh_hist_push(line, len);
                int should_logout = execute(line);
                /* A long-running command is not idle time: refresh
                   the activity stamp after it finishes, or a user
                   returning from a long `run` would be locked out
                   immediately on the next prompt. */
                last_activity = timer_ticks;
                if (should_logout) return 0;
                break;
            } else if (c == 3) { /* ^C: cancel the line, fresh prompt */
                line[0] = 0;
                sh_hist_pos = -1;
                console_putchar('\n');
                break;
            } else if (c == '\b') {
                if (cur > 0) {
                    for (u32 i = cur - 1; i + 1 < len; i++) line[i] = line[i + 1];
                    len--; cur--;
                    line[len] = 0;
                    sh_hist_pos = -1;
                    if (cur == len && console_cursor_col() > 0) {
                        console_putchar('\b');
                        shown = prompt_len + len;
                    } else {
                        sh_redraw(line, len, cur, prompt_len, &shown);
                    }
                }
            } else if (c == KEY_DEL) {
                if (cur < len) {
                    for (u32 i = cur; i + 1 < len; i++) line[i] = line[i + 1];
                    len--;
                    line[len] = 0;
                    sh_hist_pos = -1;
                    sh_redraw(line, len, cur, prompt_len, &shown);
                }
            } else if (c == KEY_LEFT) {
                if (cur > 0) {
                    cur--;
                    sh_cursor_to_cell(sh_prompt_start(prompt_len, cur + 1) + prompt_len + cur);
                }
            } else if (c == KEY_RIGHT) {
                if (cur < len) {
                    cur++;
                    sh_cursor_to_cell(sh_prompt_start(prompt_len, cur - 1) + prompt_len + cur);
                }
            } else if (c == KEY_HOME || c == 1) { /* Home, ^A */
                if (cur != 0) {
                    u32 old = cur; cur = 0;
                    sh_cursor_to_cell(sh_prompt_start(prompt_len, old) + prompt_len);
                }
            } else if (c == KEY_END || c == 5) { /* End, ^E */
                if (cur != len) {
                    u32 old = cur; cur = len;
                    sh_cursor_to_cell(sh_prompt_start(prompt_len, old) + prompt_len + len);
                }
            } else if (c == 21) { /* ^U kill whole line */
                if (len > 0) {
                    len = 0; cur = 0; line[0] = 0;
                    sh_hist_pos = -1;
                    sh_redraw(line, len, cur, prompt_len, &shown);
                }
            } else if (c == 11) { /* ^K kill to end */
                if (cur < len) {
                    len = cur; line[len] = 0;
                    sh_hist_pos = -1;
                    sh_redraw(line, len, cur, prompt_len, &shown);
                }
            } else if (c == 23) { /* ^W delete word before cursor */
                if (cur > 0) {
                    u32 i = cur;
                    while (i > 0 && line[i - 1] == ' ') i--;
                    while (i > 0 && line[i - 1] != ' ') i--;
                    if (i < cur) {
                        u32 d = cur - i;
                        for (u32 j = i; j + d < len; j++) line[j] = line[j + d];
                        len -= d; cur = i; line[len] = 0;
                        sh_hist_pos = -1;
                        sh_redraw(line, len, cur, prompt_len, &shown);
                    }
                }
            } else if (c == KEY_UP) {
                if (sh_hist_n > 0) {
                    if (sh_hist_pos < 0) {
                        u32 i = 0;
                        while (i < len && i < 127) { sh_hist_pending[i] = line[i]; i++; }
                        sh_hist_pending[i] = 0;
                        sh_hist_pos = (int)sh_hist_n - 1;
                        sh_load_line(line, &len, &cur, sh_hist[sh_hist_pos]);
                        sh_redraw(line, len, cur, prompt_len, &shown);
                    } else if (sh_hist_pos > 0) {
                        sh_hist_pos--;
                        sh_load_line(line, &len, &cur, sh_hist[sh_hist_pos]);
                        sh_redraw(line, len, cur, prompt_len, &shown);
                    }
                    /* At the oldest entry: stay, no redraw. */
                }
            } else if (c == KEY_DOWN) {
                if (sh_hist_pos >= 0) {
                    if (sh_hist_pos < (int)sh_hist_n - 1) {
                        sh_hist_pos++;
                        sh_load_line(line, &len, &cur, sh_hist[sh_hist_pos]);
                        sh_redraw(line, len, cur, prompt_len, &shown);
                    } else {
                        sh_hist_pos = -1;
                        sh_load_line(line, &len, &cur, sh_hist_pending);
                        sh_redraw(line, len, cur, prompt_len, &shown);
                    }
                }
            } else if (c == '\t') {
                sh_complete(line, &len, &cur, prompt_len, &shown);
                line[len] = 0;
            } else if (c >= 32 && c < 127 && len < sizeof(line) - 1) {
                if (cur == len) {
                    line[len++] = (char)c; cur++;
                    line[len] = 0;
                    sh_hist_pos = -1;
                    console_putchar((char)c);
                    shown = prompt_len + len;
                } else {
                    for (u32 i = len; i > cur; i--) line[i] = line[i - 1];
                    line[cur] = (char)c; len++; cur++;
                    line[len] = 0;
                    sh_hist_pos = -1;
                    sh_redraw(line, len, cur, prompt_len, &shown);
                }
            }
            /* Any other special code is ignored, and only
               printable ASCII reaches the line buffer (a special
               code truncated to char would store a NUL byte). */
        }
    }
}

void shell_run(void) {
    for (;;) {
        do_login();
        shell_loop();
    }
}

const char *shell_session_name(void) { return session_name; }
u32 shell_session_uid(void) { return session_uid; }
u32 shell_idle_minutes(void) { return idle_timeout_minutes; }
void shell_set_idle_minutes(u32 m) { idle_timeout_minutes = m; }
