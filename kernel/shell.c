#include "common.h"
#include "console.h"
#include "shell.h"
#include "users.h"
#include "proc.h"
#include "../mm/pmm.h"
#include "../drivers/pit.h"
#include "../drivers/keyboard.h"
#include "../fs/vfs.h"

static char session_name[32];
static u32 session_uid = 0;
static int session_active = 0;

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

/* Read one line from the keyboard. echo=1 prints chars, echo=0 prints
   nothing (passwords). Returns length. */
static int read_line(char *buf, u32 max, int echo) {
    u32 len = 0;
    for (;;) {
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
        u32 uid = 0;
        if (users_check(user, pass, &uid)) {
            memset(session_name, 0, sizeof(session_name));
            u32 i = 0;
            while (user[i] && i < 31) { session_name[i] = user[i]; i++; }
            session_uid = uid; session_active = 1;
            audit("login-ok", user);
            console_printf("Welcome, %s.\n", session_name);
            return 1;
        }
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

/* Returns 1 if the shell loop should exit (logout). */
static int execute(char *line) {
    char *tok[4];
    char *rest = 0;
    int n = tokenize(line, tok, &rest);
    if (n == 0) return 0;
    if (strcmp(tok[0], "help") == 0) {
        console_write("Commands: help, mem, ticks, clear, reboot, fs, ls, cat <file>, write <file> <text>, rm <file>, run <file>, whoami, logout\n");
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
        audit("logout", session_name);
        console_write("Logged out.\n");
        session_active = 0;
        return 1;
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
    for (;;) {
        console_printf("%s@nxts> ", session_name);
        len = 0;
        for (;;) {
            int c = keyboard_getchar();
            if (c < 0) {
                /* Idle session lock: 10 minutes (60000 ticks at 100 Hz).
                   NOT QEMU-tested (waiting 10 minutes in a test is not
                   feasible); the tick comparison is simple and reviewed,
                   and the lock path is documented as such. */
                if (session_active && timer_ticks - last_activity > 60000) {
                    console_write("\nSession locked due to inactivity. Enter password: ");
                    char pass[64];
                    read_line(pass, sizeof(pass), 0);
                    u32 uid = 0;
                    if (users_count() > 0 && users_check(session_name, pass, &uid) && uid == session_uid) {
                        console_write("Session unlocked.\n");
                        last_activity = timer_ticks;
                        break;
                    }
                    console_write("Unlock failed. Logging out.\n");
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
                if (execute(line)) return 0;
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
