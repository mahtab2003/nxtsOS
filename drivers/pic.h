#ifndef NXTS_PIC_H
#define NXTS_PIC_H
#include "../kernel/common.h"
void pic_init(void);
void pic_send_eoi(u8 irq);
#endif
