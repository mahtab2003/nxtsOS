#ifndef NXTS_USERS_H
#define NXTS_USERS_H
#include "common.h"
#define MAX_USERS 8
int  users_load(void); /* returns number of users loaded (0 = no users file) */
int  users_count(void);
int  users_check(const char *name, const char *password, u32 *uid_out);
const char *users_name_for_uid(u32 uid);
u32  users_hash(const char *salt, const char *password);
#endif
