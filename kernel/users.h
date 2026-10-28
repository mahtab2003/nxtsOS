#ifndef NXTS_USERS_H
#define NXTS_USERS_H
#include "common.h"
#define MAX_USERS 8
int  users_load(void); /* returns number of users loaded (0 = no users file) */
int  users_count(void);
int  users_check(const char *name, const char *password, u32 *uid_out);
int  users_exists(const char *name); /* 1 if name is a loaded account, else 0 */
const char *users_name_for_uid(u32 uid);
u32  users_hash(const char *salt, const char *password);
/* Change a loaded user's password at runtime (shell `passwd`): generate
   a fresh salt, rewrite users.txt root-owned 0600 from the loaded table
   with only that user's salt+hash replaced, reload the table, and verify
   the new password checks. 0 on success, -1 on no such user, empty new
   password, no filesystem, or write/reload failure. Other users' lines
   are re-emitted unchanged in content; lines users_load skipped as
   malformed were never usable for login and are dropped by the rewrite. */
int  users_change_password(const char *name, const char *new_password);
#endif
