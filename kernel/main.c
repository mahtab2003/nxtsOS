#include "common.h"
#include "console.h"
#include "panic.h"
#include "shell.h"
#include "../mm/pmm.h"
#include "../drivers/idt.h"
#include "../drivers/pic.h"
#include "../drivers/pit.h"
#include "../drivers/keyboard.h"
#include "../drivers/serial.h"

extern u32 __kernel_start, __kernel_end;

struct multiboot_info {
    u32 flags, mem_lower, mem_upper, boot_device, cmdline;
    u32 mods_count, mods_addr;
    u32 syms[4];
    u32 mmap_length, mmap_addr;
};

void kmain(u32 magic, u32 mbi_addr) {
    serial_init();
    console_init();
    console_write("nxtsOS kernel starting\n");
    console_write("nxtsOS v0.1.0 - original kernel, Multiboot boot\n");
    if (magic != 0x2BADB002) panic("bad Multiboot magic");
    struct multiboot_info *mbi = (struct multiboot_info *)mbi_addr;
    console_printf("Multiboot: mem_lower=%uK mem_upper=%uK mmap_len=%u\n",
                   mbi->mem_lower, mbi->mem_upper, mbi->mmap_length);
    pmm_init(mbi->mmap_addr, mbi->mmap_length,
             (u32)&__kernel_start, (u32)&__kernel_end);
    console_printf("PMM: total=%u frames free=%u frames\n",
                   pmm_total_frames(), pmm_free_frames());
    idt_init();
    pic_init();
    pit_init();
    keyboard_init();
    __asm__ volatile ("sti");
    console_write("Interrupts enabled\n");
    shell_run();
    panic("shell returned");
}
