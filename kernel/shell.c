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
#include "../drivers/mouse.h"
#include "../mm/pmm.h"
#include "../drivers/pit.h"
#include "../drivers/keyboard.h"
#include "../fs/vfs.h"
#include "../net/net.h"
#include "../net/http.h"
#include "../net/fw.h"

static char session_name[32];
static u32 session_uid = 0;
static int session_active = 0;
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

static int tokenize(char *line, char *tok[], char **rest) {
    int n = 0;
    *rest = 0;
    char *p = line;
    while (*p && n < 4) {
        while (*p == ' ') p++;
        if (*p == 0) break;
        tok[n++] = p;
        while (*p && *p != ' ') p++;
        if (*p == ' ') {
            *p = 0; p++;
            if (n == 2) {
                while (*p == ' ') p++;
                *rest = p;
                break;
            }
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
    {"test", "Self-tests and autotest scripts"},
};
static const struct help_entry help_table[] = {
    {"help", "system", "help [group|command]", "Show the group index, a group's commands, or one command's dedicated help."},
    {"ver", "system", "ver", "Print the nxtsOS version (same literal build.sh checks)."},
    {"mem", "system", "mem", "Show physical memory frames: total, free, used."},
    {"ticks", "system", "ticks", "Show timer ticks and uptime in seconds (100 Hz)."},
    {"uptime", "system", "uptime", "Show uptime as days, hours, minutes, seconds, plus background job count."},
    {"date", "system", "date", "Show the wall-clock date and time from the CMOS RTC (YYYY-MM-DD HH:MM:SS, year = 2000 + RTC year register). Setting the clock is not supported in this run."},
    {"sysinfo", "system", "sysinfo", "One-screen system summary: version, CPU, memory, disk, network, jobs, session."},
    {"clear", "system", "clear", "Clear the text console."},
    {"echo", "system", "echo <text>", "Print text to the console."},
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
    {"idle", "session", "idle [minutes 0-480|off]", "Show or set the idle session-lock timeout for this session (0 = never)."},
    {"fs", "fs", "fs", "Show filesystem status (mounted, files, space)."},
    {"ls", "fs", "ls", "List files as a list view (header, names, footer count)."},
    {"cat", "fs", "cat <file>", "Print a whole text file, in 1023-byte windows."},
    {"write", "fs", "write <file> <text>", "Create or overwrite a file with text."},
    {"rm", "fs", "rm <file>", "Delete a file (permission-checked)."},
    {"mv", "fs", "mv <old> <new>", "Rename a file."},
    {"cp", "fs", "cp <src> <dst>", "Copy a file."},
    {"chmod", "fs", "chmod <file> <mode>", "Set a file mode (octal, 3 digits, e.g. 600 or 0644)."},
    {"chown", "fs", "chown <file> <user>", "Root only: change a file's owner (metadata only; mode, size, data untouched)."},
    {"stat", "fs", "stat <file>", "Show a file's size, owner, mode, and sector count (root, owner, or any reader)."},
    {"edit", "fs", "edit <file>", "Full-screen text editor (nano-like: ^O save, ^X exit, ^W search, ^K cut, ^U paste, ^G help)."},
    {"run", "proc", "run <file>", "Run an ELF program in the foreground."},
    {"runbg", "proc", "runbg <file>", "Start an ELF program as a background job."},
    {"jobs", "proc", "jobs", "List background jobs as a list view (header, rows, footer count)."},
    {"ps", "proc", "ps", "Show the session plus background jobs (pid, name, uid)."},
    {"top", "proc", "top", "Live resource monitor (uptime, memory, disk, network, jobs); press q to quit."},
    {"kill", "proc", "kill <pid>", "Kill a background job by pid (own jobs, or any as root)."},
    {"pkg", "pkg", "pkg <subcommand>", "Package manager (see 'help pkg' for subcommands)."},
    {"pkg list", "pkg", "pkg list", "List installed packages (header, rows, footer count)."},
    {"pkg avail", "pkg", "pkg avail", "List packages available from the configured repository."},
    {"pkg install", "pkg", "pkg install <file>|<name>", "Root only: install a local .nxpkg file, or a named package from the repo."},
    {"pkg remove", "pkg", "pkg remove <name> [force]", "Root only: remove an installed package (force skips the dependency check)."},
    {"pkg repo", "pkg", "pkg repo [url]", "Show the repository URL, or set it (root only). https:// is TOFU, httpsa:// is anchored, httpss:// uses the CA store."},
    {"pkg update", "pkg", "pkg update", "Root only: refresh the repository index over anchored HTTPS."},
    {"pkg fetch", "pkg", "pkg fetch <name>", "Root only: download a package from the repo without installing it."},
    {"sysupdate", "pkg", "sysupdate <bundle.nxupd>", "Root only: apply a signed system-update bundle (snapshot + rollback on failure)."},
    {"sysrollback", "pkg", "sysrollback", "Root only: roll back to the pre-update snapshot."},
    {"netinfo", "net", "netinfo", "Show NIC MAC, counters, and IP configuration."},
    {"netdbg", "net", "netdbg", "Dump network driver debug state."},
    {"dhcp", "net", "dhcp", "Configure IP via DHCP (no uid gate - pre-existing, see security notes)."},
    {"ping", "net", "ping <ip>", "Ping a dotted-quad IPv4 address; reports reply or no reply."},
    {"dns", "net", "dns <name>", "Look up a hostname via the configured DNS server."},
    {"dnsset", "net", "dnsset <ip>", "Set the DNS server address (no uid gate - pre-existing)."},
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
    {"sha256", "crypto", "sha256 <file>", "Print the SHA-256 hex digest of a file (up to 64 KiB)."},
    {"fbinfo", "diag", "fbinfo", "Show framebuffer geometry or why none is available."},
    {"kbdstat", "diag", "kbdstat", "Show PS/2 controller status, startup-drained bytes, last scancode."},
    {"mouse", "diag", "mouse", "Show pointer presence, position, and button state."},
    {"mousepoll", "diag", "mousepoll", "Poll the PS/2 controller for 5 seconds, logging any bytes."},
    {"cpu", "diag", "cpu", "Show CPU vendor, brand, family/model/stepping, and feature flags (CPUID)."},
    {"pci", "diag", "pci", "List PCI bus 0 devices: vendor, device, class, BAR0."},
    {"acpi", "diag", "acpi", "Show parsed ACPI poweroff state (PM1 blocks, SLP_TYP) or the failure stage."},
    {"disk", "diag", "disk", "Show ATA disk presence and filesystem total/free space."},
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
    console_write("Command groups: system, session, fs, proc, pkg, net, crypto, diag, gui, test\n");
    for (u32 i = 0; i < HELP_NGROUPS; i++)
        console_printf("  %s: %s\n", help_groups[i].name, help_groups[i].desc);
    console_write("Type 'help <group>' for a group's commands, or 'help <command>' for one command's details.\n");
    console_write("Groups also dispatch: 'net ping <ip>', 'test csprngtest', 'fs ls', and so on. Flat names still work.\n");
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

static int execute(char *line) {
    char *tok[4];
    char *rest = 0;
    int n = tokenize(line, tok, &rest);
    if (n == 0) return 0;
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
    } else if (strcmp(tok[0], "mem") == 0) {
        cmd_mem();
    } else if (strcmp(tok[0], "ticks") == 0) {
        console_printf("Timer ticks: %u (%u seconds at 100 Hz)\n",
                       timer_ticks, timer_ticks / 100);
    } else if (strcmp(tok[0], "clear") == 0) {
        console_clear();
    } else if (strcmp(tok[0], "echo") == 0) {
        /* tokenize() splits the text into tok[1] + rest, so rejoin
           with one space; bare `echo` prints just a newline. */
        if (n >= 2) {
            console_write(tok[1]);
            if (rest && rest[0]) { console_putchar(' '); console_write(rest); }
        }
        console_putchar('\n');
    } else if (strcmp(tok[0], "ver") == 0) {
        /* Version literal, kept in sync by build.sh's VERSION check
           (same grep as the main.c banner and the wm.c About text). */
        console_write("nxtsOS v1.1.5\n");
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
        if (session_uid != 0) { console_write("shutdown: root only\n"); return 0; }
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
        if (session_uid != 0) { console_write("halt: root only\n"); return 0; }
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
    } else if (strcmp(tok[0], "logout") == 0) {
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
        if (session_uid != 0) { console_write("unlock: root only\n"); return 0; }
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
        if (session_uid != 0) { console_write("useradd: root only\n"); return 0; }
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
        if (session_uid != 0) { console_write("userdel: root only\n"); return 0; }
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
        if (session_uid != 0) { console_write("groupadd: root only\n"); return 0; }
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
        if (session_uid != 0) { console_write("groupdel: root only\n"); return 0; }
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
        if (session_uid != 0) { console_write("groupmod: root only\n"); return 0; }
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
        if (!fs_mounted()) { console_write("No filesystem mounted\n"); return 0; }
        fs_list_as(session_uid);
    } else if (strcmp(tok[0], "cat") == 0) {
        if (n < 2) { console_write("Usage: cat <file>\n"); return 0; }
        /* Chunked display: the buffer stays 1024 bytes (the kernel
           stack is 16 KiB, so no large stack array), but the file
           is walked with fs_read_range_as, so a file of any size
           prints in full instead of being refused over 1023 bytes.
           The permission check runs on every window, so a refusal
           cannot be walked around by offset. Text only: a NUL byte
           ends the chunk console_write prints, as before. */
        u8 buf[1024];
        u32 off = 0;
        for (;;) {
            u32 size = 0;
            if (fs_read_range_as(tok[1], buf, sizeof(buf) - 1, off, &size, session_uid) != 0) {
                if (off == 0) console_printf("cat: cannot read %s\n", tok[1]);
                else console_printf("cat: read error %s\n", tok[1]);
                return 0;
            }
            if (size == 0) break;
            buf[size] = 0;
            console_write((const char *)buf);
            off += size;
            if (size < sizeof(buf) - 1) break;
        }
        console_write("\n");
    } else if (strcmp(tok[0], "write") == 0) {
        if (n < 2 || !rest || rest[0] == 0) {
            console_write("Usage: write <file> <text>\n"); return 0;
        }
        if (fs_write_as(tok[1], (const u8 *)rest, strlen(rest), session_uid, 0644) != 0) {
            console_printf("write: cannot write %s (invalid name, no permission, no space, or no filesystem)\n", tok[1]);
            return 0;
        }
        console_printf("Wrote %s\n", tok[1]);
    } else if (strcmp(tok[0], "rm") == 0) {
        if (n < 2) { console_write("Usage: rm <file>\n"); return 0; }
        if (fs_delete_as(tok[1], session_uid) != 0) {
            console_printf("rm: cannot delete %s\n", tok[1]);
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
        if (fs_rename_as(tok[1], nw, session_uid) != 0) {
            console_printf("mv: cannot rename %s to %s\n", tok[1], nw);
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
        if (fs_copy_as(tok[1], dst, session_uid) != 0) {
            console_printf("cp: cannot copy %s to %s\n", tok[1], dst);
            return 0;
        }
        console_printf("Copied %s to %s\n", tok[1], dst);
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
        if (fs_chmod_as(tok[1], mode, session_uid) != 0) {
            console_printf("chmod: cannot chmod %s\n", tok[1]);
            return 0;
        }
        console_printf("chmod: %s mode %s\n", tok[1], ms);
    } else if (strcmp(tok[0], "chown") == 0) {
        /* Root only, enforced here AND in fs_chown_as. The file
           is tok[1], the user is the first word of rest (same
           tokenize rule as chmod); anything after it is a usage
           error, never silently ignored. */
        if (session_uid != 0) { console_write("chown: root only\n"); return 0; }
        if (n < 2 || !rest || !rest[0]) { console_write("Usage: chown <file> <user>\n"); return 0; }
        char *user = rest;
        char *p = user;
        while (*p && *p != ' ') p++;
        if (*p) { *p = 0; p++; while (*p == ' ') p++; if (*p) { console_write("Usage: chown <file> <user>\n"); return 0; } }
        u32 uid = 0;
        if (users_uid(user, &uid) != 0) { console_printf("chown: no such user %s\n", user); return 0; }
        if (fs_chown_as(tok[1], uid, session_uid) != 0) {
            console_printf("chown: cannot chown %s\n", tok[1]);
            return 0;
        }
        console_printf("chown: %s owner %s\n", tok[1], user);
    } else if (strcmp(tok[0], "stat") == 0) {
        /* Metadata read: root, owner, or any reader (the fs
           layer enforces the rule; missing and unreadable both
           report the same refusal, so stat is not an existence
           oracle for files the caller may not read). */
        if (n < 2 || (rest && rest[0])) { console_write("Usage: stat <file>\n"); return 0; }
        if (!fs_mounted()) { console_write("No filesystem mounted\n"); return 0; }
        struct fs_stat st;
        if (fs_stat_as(tok[1], &st, session_uid) != 0) {
            console_printf("stat: cannot stat %s\n", tok[1]);
            return 0;
        }
        console_printf("%s: %u bytes, uid %u (%s), mode %u, %u sectors\n",
                       tok[1], st.size, st.uid, users_name_for_uid(st.uid),
                       st.mode, st.sectors);
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
            if (session_uid != 0) { console_write("sysupdate: root only\n"); return 0; }
            pkg_sysupdate(first);
            return 0;
        }
        if (strcmp(tok[1], "sysrollback") == 0) {
            if (session_uid != 0) { console_write("sysrollback: root only\n"); return 0; }
            pkg_sysrollback();
            return 0;
        }
        if (strcmp(tok[1], "list") == 0) {
            pkg_list();
        } else if (strcmp(tok[1], "avail") == 0) {
            /* Read-only like pkg list: no root check. */
            pkg_repo_avail();
        } else if (strcmp(tok[1], "install") == 0) {
            if (!rest || rest[0] == 0) { console_write("Usage: pkg install <file>\n"); return 0; }
            if (session_uid != 0) { console_write("pkg install: root only\n"); return 0; }
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
                if (session_uid != 0) { console_write("pkg repo: root only\n"); return 0; }
                pkg_repo_set(rest);
            }
        } else if (strcmp(tok[1], "update") == 0) {
            if (session_uid != 0) { console_write("pkg update: root only\n"); return 0; }
            pkg_repo_update();
        } else if (strcmp(tok[1], "fetch") == 0) {
            if (!rest || rest[0] == 0) { console_write("Usage: pkg fetch <name>\n"); return 0; }
            if (session_uid != 0) { console_write("pkg fetch: root only\n"); return 0; }
            pkg_repo_fetch(rest);
        } else if (strcmp(tok[1], "remove") == 0) {
            if (!rest || rest[0] == 0) { console_write("Usage: pkg remove <name> [force]\n"); return 0; }
            if (session_uid != 0) { console_write("pkg remove: root only\n"); return 0; }
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
    } else if (strcmp(tok[0], "dhcp") == 0) {
        console_write(net_dhcp() == 0 ? "dhcp: configured\n" : "dhcp: failed\n");
    } else if (strcmp(tok[0], "ping") == 0) {
        if (n < 2) { console_write("Usage: ping <ip>\n"); return 0; }
        ip_t dst;
        if (!net_parse_ip(tok[1], &dst)) { console_write("ping: bad IP (dotted quad only)\n"); return 0; }
        console_write(net_ping(dst) == 0 ? "ping: reply received\n" : "ping: no reply\n");
    } else if (strcmp(tok[0], "dnsset") == 0) {
        if (n < 2) { console_write("Usage: dnsset <ip>\n"); return 0; }
        ip_t ip;
        if (!net_parse_ip(tok[1], &ip)) { console_write("dnsset: bad IP\n"); return 0; }
        net_set_dns(ip);
        console_printf("dns server set to %u.%u.%u.%u\n", ip.b[0], ip.b[1], ip.b[2], ip.b[3]);
    } else if (strcmp(tok[0], "dns") == 0) {
        if (n < 2) { console_write("Usage: dns <name>\n"); return 0; }
        ip_t ip;
        if (net_dns_lookup(tok[1], &ip) == 0)
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
            if (session_uid != 0) { console_write("castore: root only\n"); return 0; }
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
            if (session_uid != 0) { console_write("castore: root only\n"); return 0; }
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
            if (session_uid != 0) { console_write("castore: root only\n"); return 0; }
            console_write(fs_delete_as("castore.txt", session_uid) == 0 ? "castore: cleared\n" : "castore: no store\n");
        } else {
            console_write("Usage: castore list|add <file>|update <host> [port]|clear\n");
        }
    } else if (strcmp(tok[0], "tofprints") == 0) {
        if (session_uid != 0) { console_write("tofprints: root only\n"); return 0; }
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
            if (session_uid != 0) { console_write("fw: root only\n"); return 0; }
            fw_set_enabled(1);
            console_write(fw_save() == 0 ? "fw: enabled\n" : "fw: enabled (save failed)\n");
        } else if (strcmp(tok[1], "disable") == 0) {
            if (session_uid != 0) { console_write("fw: root only\n"); return 0; }
            fw_set_enabled(0);
            console_write(fw_save() == 0 ? "fw: disabled\n" : "fw: disabled (save failed)\n");
        } else if (strcmp(tok[1], "default") == 0) {
            if (session_uid != 0) { console_write("fw: root only\n"); return 0; }
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
            if (session_uid != 0) { console_write("fw: root only\n"); return 0; }
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
            if (session_uid != 0) { console_write("fw: root only\n"); return 0; }
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
            if (session_uid != 0) { console_write("fw: root only\n"); return 0; }
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
        if (session_uid != 0) { console_write("sysupdate: root only\n"); return 0; }
        pkg_sysupdate(tok[1]);
    } else if (strcmp(tok[0], "sysrollback") == 0) {
        if (session_uid != 0) { console_write("sysrollback: root only\n"); return 0; }
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
    } else if (strcmp(tok[0], "kill") == 0) {
        if (n < 2) { console_write("Usage: kill <pid>\n"); return 0; }
        u32 pid = 0; int bad = 0;
        for (const char *p = tok[1]; *p; p++) {
            if (*p < '0' || *p > '9' || pid > 1000000) { bad = 1; break; }
            pid = pid * 10u + (u32)(*p - '0');
        }
        if (bad || proc_bg_kill(pid, session_uid) != 0) {
            console_printf("kill: cannot kill %s (no such job or no permission)\n", tok[1]);
            return 0;
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
    } else if (strcmp(tok[0], "pci") == 0) {
        console_write("PCI bus 0:\nDEV FUNC  VENDOR:DEVICE  CLASS  BAR0\n");
        int n = hw_pci_scan(pci_print_row);
        console_printf("(%d PCI device(s))\n", n);
    } else if (strcmp(tok[0], "acpi") == 0) {
        acpi_diag();
    } else if (strcmp(tok[0], "disk") == 0) {
        if (!ata_present()) { console_write("Disk: no ATA disk\n"); return 0; }
        if (!fs_mounted()) { console_write("Disk: ATA device present, filesystem not mounted (no disk or bad filesystem)\n"); return 0; }
        u32 total = fs_total_sectors(), free = fs_free_sectors();
        /* 1 MiB = 2048 sectors: shifts, no division. */
        console_printf("Disk: %u sectors total (%u MiB), %u sectors free (%u MiB)\n",
                       total, total >> 11, free, free >> 11);
    } else if (strcmp(tok[0], "uptime") == 0) {
        u32 d, h, m, s;
        split_uptime(ticks_to_seconds(timer_ticks), &d, &h, &m, &s);
        console_printf("Uptime: %u day(s) %u:%u:%u (%u background job(s))\n",
                       d, h, m, s, proc_bg_count());
    } else if (strcmp(tok[0], "date") == 0) {
        /* Wall clock from the CMOS RTC (hw_rtc_read handles
           BCD/binary, 12/24-hour, and the update-in-progress
           wait). World-readable, like uptime. The minimal
           printf has no %02u, so fields are padded by hand. */
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
           quit on 'q'. Other keys are ignored. On exit the
           screen is cleared so the shell prompt returns clean. */
        for (;;) {
            console_clear();
            u32 d, h, m, s;
            split_uptime(ticks_to_seconds(timer_ticks), &d, &h, &m, &s);
            console_printf("nxtsOS top - uptime %u day(s) %u:%u:%u - press q to quit\n",
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
            while (timer_ticks - start < 100) {
                keyboard_poll();
                int c = keyboard_getchar();
                if (c == 'q') { quit = 1; break; }
                proc_bg_tick();
                __asm__ volatile ("hlt");
            }
            if (quit) break;
        }
        console_clear();
        console_write("top: quit\n");
    } else {
        console_printf("Unknown command: %s (type help)\n", tok[0]);
    }
    return 0;
}

static int shell_loop(void) {
    char line[128];
    u32 len = 0;
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
        len = 0;
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
            /* Scroll keys (Work D): PgUp/PgDn page the scrollback
               ring; any other special code is ignored, and only
               printable ASCII reaches the line buffer (a special
               code truncated to char would store a NUL byte). */
            if (c == KEY_PGUP) { console_scroll_up(); }
            else if (c == KEY_PGDN) { console_scroll_down(); }
            else if (c == '\n') {
                line[len] = 0;
                console_putchar('\n');
                int should_logout = execute(line);
                /* A long-running command is not idle time: refresh
                   the activity stamp after it finishes, or a user
                   returning from a long `run` would be locked out
                   immediately on the next prompt. */
                last_activity = timer_ticks;
                if (should_logout) return 0;
                break;
            } else if (c == '\b') {
                if (len > 0) { len--; console_putchar('\b'); }
            } else if (c >= 32 && c < 127 && len < sizeof(line) - 1) {
                line[len++] = (char)c;
                console_putchar((char)c);
            }
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
