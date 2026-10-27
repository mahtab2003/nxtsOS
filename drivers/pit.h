#ifndef NXTS_PIT_H
#define NXTS_PIT_H
#include "../kernel/common.h"
extern volatile u32 timer_ticks;
void pit_init(void);
void timer_tick(void);
#endif
