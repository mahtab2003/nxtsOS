#ifndef NXTS_PKG_H
#define NXTS_PKG_H
#include "common.h"
int  pkg_list(void);
int  pkg_install(const char *pkgfile);
int  pkg_remove(const char *name, int force);
int  pkg_verify_file(const char *name, const u8 *data, u32 len);
int  pkg_sysupdate(const char *bundlefile);
int  pkg_sysrollback(void);
int  pkg_repo_show(void);
int  pkg_repo_set(const char *url);
int  pkg_repo_update(void);
int  pkg_repo_fetch(const char *name);
int  pkg_repo_install(const char *name);
#endif
