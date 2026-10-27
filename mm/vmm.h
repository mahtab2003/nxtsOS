#ifndef NXTS_VMM_H
#define NXTS_VMM_H
#include "../kernel/common.h"
#define PAGE_PRESENT 0x1
#define PAGE_RW      0x2
#define PAGE_USER    0x4
#define USER_BASE        0x08048000u
#define USER_STACK_TOP   0x0C000000u
#define USER_STACK_PAGE  0x0BFFF000u
#define KERNEL_MAP_END   0x02000000u /* identity-mapped kernel region: 0-32 MB */

void vmm_init(void);
u32  vmm_kernel_pd(void);
u32  vmm_create_pd(void);
void vmm_map_page(u32 pd_phys, u32 virt, u32 phys, u32 flags);
u32  vmm_map_user(u32 pd_phys, const u8 *blob, u32 blob_size); /* returns code pages */
void vmm_enable_paging(u32 pd_phys);
#endif
