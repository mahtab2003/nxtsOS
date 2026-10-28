#ifndef NXTS_PKG_H
#define NXTS_PKG_H
#include "common.h"
int  pkg_list(void);
/* Installed-package registry entry for desktop windows: copies the
   idx-th entry's name (<=31 chars) and version (<=15 chars), both
   NUL-terminated. Returns 0, or -1 if idx is out of range or the
   registry cannot be read. Read-only: it never writes the registry. */
int  pkg_registry_entry(int idx, char *name, char *version);
int  pkg_install(const char *pkgfile);
int  pkg_remove(const char *name, int force);
int  pkg_verify_file(const char *name, const u8 *data, u32 len);
/* Vendor-signature check over arbitrary bytes (package trust
   anchors: compiled-in vendor key, then pubkeys.txt keyring).
   Used by the CA-store updater for signed store bundles. */
int  pkg_verify_vendor_sig(const u8 *msg, u32 msg_len, const u8 *sig);
int  pkg_sysupdate(const char *bundlefile);
int  pkg_sysrollback(void);
int  pkg_repo_show(void);
int  pkg_repo_set(const char *url);
/* Shell `pkg avail` (6(c) part 3, repo tooling): read-only list of
   the packages available from the repository, for shell users who
   have no desktop Repo window — `pkg repo` alone prints only the
   URL, so before this a shell user had to guess names for
   `pkg install <name>`. It reuses the Repo window's verified
   load path (browse_load re-verifies the stored index signature),
   so a missing or unverifiable stored index prints the no-index
   message, never stale or unverified entries. No root check:
   read-only like `pkg list` and the Repo window. */
int  pkg_repo_avail(void);
int  pkg_repo_update(void);
int  pkg_repo_fetch(const char *name);
int  pkg_repo_install(const char *name);
/* Repo browser window (6b utility app): read-only views over the
   stored, signature-verified repo index. config_url copies the
   repo.txt URL (0, or -1 if none set). browse_load re-verifies
   the stored index and returns its entry count (or -1 if there
   is no verified stored index); browse_entry then copies one
   entry from that load. Nothing here writes or fetches. */
int  pkg_repo_config_url(char *url, u32 url_max);
int  pkg_repo_browse_load(u32 *version_out);
int  pkg_repo_browse_entry(int idx, char *name, char *version);
#endif
