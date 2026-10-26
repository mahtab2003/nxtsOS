#ifndef NXTS_ELF_H
#define NXTS_ELF_H
#include "common.h"
#include "proc.h"
/* Load an ELF32 file from disk into a fresh process address space.
   Returns 0 on success (proc filled in, including pd, eip, esp,
   code_pages), -1 on any validation failure. On failure the caller
   must destroy the created page directory (elf_create_proc does that
   itself and returns -1 with pd set to 0). */
int elf_create_proc(const char *name, u32 uid, struct proc *p);
#endif
