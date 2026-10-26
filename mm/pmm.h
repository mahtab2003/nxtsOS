#ifndef NXTS_PMM_H
#define NXTS_PMM_H
#include "../kernel/common.h"
void pmm_init(u32 mmap_addr, u32 mmap_len, u32 kstart, u32 kend);
u32  pmm_alloc_frame(void);
void pmm_free_frame(u32 addr);
u32  pmm_total_frames(void);
u32  pmm_free_frames(void);
u32  pmm_used_frames(void);
#endif
