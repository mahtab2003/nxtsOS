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
/* Name rules for accounts (and, by reuse, for groups): 1-31 chars,
   every char printable (33-126), no ':' (the file format's field
   separator). "root" is reserved: uid 0 is implicit, never a
   users.txt account, so no account or group may take the name. */
int  users_valid_name(const char *name);
/* Resolve a username to its uid: "root" -> 0, a loaded account ->
   its uid. 0 on success, -1 on unknown name. Used by `chown`
   (root may give a file to root) and by the group commands. */
int  users_uid(const char *name, u32 *uid_out);
/* Add a user at runtime (shell `useradd`, root-gated by the
   caller): validate the name, refuse duplicates and the
   MAX_USERS cap, assign uid = max existing + 1 (1000 for the
   first account; uid 0 never assigned; over the 100000 load
   cap refused), generate a CSPRNG salt, rewrite users.txt
   root-owned 0600 from the loaded table plus the new line,
   reload, and verify the new password checks. If no users.txt
   exists, the file is created with just the new user (after
   that, setup mode ends and logins use the file). 0 on
   success, -1 on bad name, empty password, duplicate, cap,
   no filesystem, or write/reload/verify failure. */
int  users_add(const char *name, const char *password);
/* Delete a user at runtime (shell `userdel`, root-gated by the
   caller): rewrite users.txt without the user, reload, and
   verify the user is gone. "root" is not a users.txt account
   and is refused by the shell before this is called; deleting
   the session user is likewise refused by the shell. 0 on
   success, -1 on no such user, no filesystem, or
   write/reload failure. */
int  users_delete(const char *name);
/* Change a loaded user's password at runtime (shell `passwd`): generate
   a fresh salt, rewrite users.txt root-owned 0600 from the loaded table
   with only that user's salt+hash replaced, reload the table, and verify
   the new password checks. 0 on success, -1 on no such user, empty new
   password, no filesystem, or write/reload failure. Other users' lines
   are re-emitted unchanged in content; lines users_load skipped as
   malformed were never usable for login and are dropped by the rewrite. */
int  users_change_password(const char *name, const char *new_password);
#endif
