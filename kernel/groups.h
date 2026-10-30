#ifndef NXTS_GROUPS_H
#define NXTS_GROUPS_H
#include "common.h"
#define MAX_GROUPS 8
#define MAX_GROUP_MEMBERS 8
/* groups.txt: lines "name:gid:member1,member2" (members part may be
   empty). Root-owned 0600, same load/rewrite discipline as
   users.txt: malformed lines are skipped on load, never fatal;
   every mutation rewrites the whole file from the loaded table
   and reloads to verify. Groups are managed account membership
   + display (id/groups) only: nxtsFS entries carry no group
   field, so group-based file permission enforcement is a future
   on-disk format change, recorded as remaining work — never
   half-implemented here. */
int  groups_load(void); /* returns number of groups loaded (0 = no groups file) */
int  groups_count(void);
int  groups_exists(const char *name); /* 1 if a loaded group, else 0 */
/* Resolve a group name to its gid. 0 on success, -1 on unknown group. */
int  groups_gid(const char *name, u32 *gid_out);
/* Create a group (shell `groupadd`, root-gated by the caller):
   gid auto-assigned = max existing + 1 (1000 for the first
   group; over the 100000 load cap refused). Returns the new
   gid on success, -1 on bad name, duplicate, cap, no
   filesystem, or write/reload failure. No groups.txt yet means
   the file is created with just the new group. */
int  groups_add(const char *name);
/* Delete a group (shell `groupdel`, root-gated by the caller).
   0 on success, -1 on no such group, no filesystem, or
   write/reload failure. */
int  groups_delete(const char *name);
/* Membership changes (shell `groupmod`, root-gated by the
   caller). The user must be a loaded account or "root".
   Returns 0 on success, 1 when the change is a no-op that
   must be reported, not silently accepted (add of an existing
   member / remove of a non-member), -2 when the group is full
   (8 members), -1 on no such group, no such user, no
   filesystem, or write/reload failure. */
int  groups_mod_add(const char *group, const char *user);
int  groups_mod_remove(const char *group, const char *user);
/* Comma-separated group names for a user ("staff,dev"), or an
   empty string when the user belongs to no group. Returns the
   group count. `out` is always NUL-terminated; overlong output
   is refused (returns -1) rather than truncated. */
int  groups_names_for_user(const char *user, char *out, u32 cap);
#endif
