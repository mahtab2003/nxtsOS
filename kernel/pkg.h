#ifndef NXTS_PKG_H
#define NXTS_PKG_H
#include "common.h"
int  pkg_list(void);
int  pkg_install(const char *pkgfile);
int  pkg_remove(const char *name, int force);
int  pkg_verify_file(const char *name, const u8 *data, u32 len);
#endif
