#ifndef NXTS_SHELL_H
#define NXTS_SHELL_H
void shell_run(void);
/* Phase 8 desktop accessors (shell session state lives in shell.c). */
const char *shell_session_name(void);
u32 shell_session_uid(void);
/* Unlock primitive (fails_clear + audit, no uid check — the caller
   must enforce root first, as the shell `unlock` command does). */
int shell_unlock_user(const char *name); /* 1 unlocked, 0 no such user */
u32 shell_idle_minutes(void);
void shell_set_idle_minutes(u32 m);
#endif
