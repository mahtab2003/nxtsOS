#include "common.h"
#include "console.h"
#include "shell.h"
#include "users.h"
#include "proc.h"
#include "pkg.h"
#include "sha256.h"
#include "aes.h"
#include "wm.h"
#include "fb.h"
#include "../drivers/mouse.h"
#include "../mm/pmm.h"
#include "../drivers/pit.h"
#include "../drivers/keyboard.h"
#include "../fs/vfs.h"
#include "../net/net.h"

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

/* Returns 1 if the shell loop should exit (logout). */
static int execute(char *line) {
    char *tok[4];
    char *rest = 0;
    int n = tokenize(line, tok, &rest);
    if (n == 0) return 0;
    if (strcmp(tok[0], "help") == 0) {
        console_write("Commands: help, mem, ticks, clear, reboot, fs, ls, cat <file>, write <file> <text>, rm <file>, run <file>, runbg <file>, jobs, kill <pid>, lock, unlock <user>, whoami, logout, idle [minutes|off], fbinfo, kbdstat, pkg list, pkg install <file>, pkg remove <name>, pkg remove <name> force, sha256 <file>, aes-test, gui, guitest, cursortest, cliptest, desktop, desktopautotest, desktopsectest, desktop10test, desktopappstest, desktop10sec, desktopwebtest, desktopnonic, mouse, netinfo, dhcp, ping <ip>, dns <name>, http <host> <path>, https <host> <path>, nettest\n");
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
    } else if (strcmp(tok[0], "reboot") == 0) {
        console_write("Rebooting...\n");
        outb(0x64, 0xFE);
        for (;;) __asm__ volatile ("hlt");
    } else if (strcmp(tok[0], "whoami") == 0) {
        console_printf("%s uid %u\n", session_name, session_uid);
    } else if (strcmp(tok[0], "logout") == 0) {
        int killed = proc_bg_kill_for_uid(session_uid);
        if (killed > 0) console_printf("Killed %u background job(s) on logout.\n", killed);
        audit("logout", session_name);
        console_write("Logged out.\n");
        session_active = 0;
        return 1;
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
        fails_clear(tok[1]);
        audit("unlock", tok[1]);
        console_printf("Unlocked %s\n", tok[1]);
        return 0;
    } else if (strcmp(tok[0], "fs") == 0) {
        fs_status();
    } else if (strcmp(tok[0], "ls") == 0) {
        if (!fs_mounted()) { console_write("No filesystem mounted\n"); return 0; }
        fs_list_as(session_uid);
    } else if (strcmp(tok[0], "cat") == 0) {
        if (n < 2) { console_write("Usage: cat <file>\n"); return 0; }
        u8 buf[1024];
        u32 size = 0;
        if (fs_read_as(tok[1], buf, sizeof(buf) - 1, &size, session_uid) != 0) {
            console_printf("cat: cannot read %s\n", tok[1]);
            return 0;
        }
        buf[size] = 0;
        console_write((const char *)buf);
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
        if (n < 2) { console_write("Usage: pkg list | pkg install <file> | pkg remove <name> [force]\n"); return 0; }
        if (strcmp(tok[1], "list") == 0) {
            pkg_list();
        } else if (strcmp(tok[1], "install") == 0) {
            if (!rest || rest[0] == 0) { console_write("Usage: pkg install <file>\n"); return 0; }
            if (session_uid != 0) { console_write("pkg install: root only\n"); return 0; }
            pkg_install(rest);
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
            console_write("Usage: pkg list | pkg install <file> | pkg remove <name> [force]\n");
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
    } else if (strcmp(tok[0], "desktop") == 0) {
        wm_desktop_run();
    } else if (strcmp(tok[0], "desktopautotest") == 0) {
        wm_desktop_autotest();
    } else if (strcmp(tok[0], "desktopsectest") == 0) {
        wm_desktop_sectest();
    } else if (strcmp(tok[0], "desktopcalctest") == 0) {
        wm_desktop_calctest();
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
        if (n < 2 || !rest || !rest[0]) { console_write("Usage: http <host> <path> [port]\n"); return 0; }
        char *path = rest;
        char *sp = path;
        while (*sp && *sp != ' ') sp++;
        u16 port = 80;
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
        static char body[8192];
        int bl = net_http_get(tok[1], port, path, body, sizeof(body));
        if (bl < 0) console_write("http: failed\n");
        else console_printf("http: %d bytes%s\n%s\n", bl, net_fetch_truncated() ? " (truncated)" : "", body);
    } else if (strcmp(tok[0], "https") == 0) {
        if (n < 2 || !rest || !rest[0]) { console_write("Usage: https <host> <path> [port]\n"); return 0; }
        char *path = rest;
        char *sp = path;
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
        static char body[8192];
        int bl = net_https_get(tok[1], port, path, body, sizeof(body));
        if (bl == -2) console_write("https: certificate refused, connection not made\n");
        else if (bl < 0) console_write("https: failed\n");
        else console_printf("https: %d bytes%s\n%s\n", bl, net_fetch_truncated() ? " (truncated)" : "", body);
    } else if (strcmp(tok[0], "nettest") == 0) {
        console_write(net_test_run() == 0 ? "nettest PASS\n" : "nettest FAIL\n");
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
                   `lock` command; waiting out the full timeout in
                   a test is still not feasible, and that is
                   documented as such. */
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
            if (c == '\n') {
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
            } else if (len < sizeof(line) - 1) {
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
