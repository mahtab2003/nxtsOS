#ifndef NXTS_GROUPS_H
#define NXTS_GROUPS_H
#include "common.h"
#define MAX_GROUPS 8
#define MAX_GROUP_MEMBERS 8
/* groups.txt: lines "name:gid:member1,member2" (members part may be
   empty). Root-owned 0600, same load/rewrite discipline as
   users.txt: malformed lines are skipped on load, never fatal;
   every mutation rewrites the whole file from the loaded table
   and reloads to verify. Groups are membership + display
   (id/groups) AND file permission enforcement (parity run):
   nxtsFS dir_entry.reserved[0] holds the file's gid with ZERO
   layout change (64-byte entries, same sector counts), so old
   disks read identically (reserved[0] = 0 = "no group") and no
   migration exists at all. */
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
/* Primary group of a user: the first group in groups.txt (file
   order) containing the user, else 0. Root and users in no
   group get 0 ("no group" — the group rule never grants for
   gid 0, so old files with reserved[0] = 0 behave exactly as
   before group enforcement existed). */
u32  groups_primary_gid(u32 uid);
/* Membership test used by the fs permission rules (parity run).
   Loads groups.txt fresh (groupmod takes effect immediately).
   gid 0 is never a membership (returns 0). */
int  groups_user_in_gid(u32 uid, u32 gid);
/* Name of a gid for display (stat). 0 on success, -1 unknown. */
int  groups_name_for_gid(u32 gid, char *out, u32 cap);
#endif
