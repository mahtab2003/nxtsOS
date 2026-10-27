#include "common.h"
#include "console.h"
#include "panic.h"
#include "shell.h"
#include "proc.h"
#include "enc.h"
#include "fb.h"
#include "../mm/pmm.h"
#include "../mm/vmm.h"
#include "../drivers/gdt.h"
#include "../drivers/idt.h"
#include "../drivers/pic.h"
#include "../drivers/pit.h"
#include "../drivers/keyboard.h"
#include "../drivers/mouse.h"
#include "../drivers/serial.h"
#include "../fs/vfs.h"
#include "../net/net.h"

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
    console_write("nxtsOS v1.0.0 - original kernel, Multiboot boot\n");
    if (magic != 0x2BADB002) panic("bad Multiboot magic");
    /* Save framebuffer info NOW, before PMM can overwrite GRUB's
       Multiboot info page (see fb_parse). */
    int fb_present = fb_parse(mbi_addr);
    struct multiboot_info *mbi = (struct multiboot_info *)mbi_addr;
    console_printf("Multiboot: mem_lower=%uK mem_upper=%uK mmap_len=%u\n",
                   mbi->mem_lower, mbi->mem_upper, mbi->mmap_length);
    pmm_init(mbi->mmap_addr, mbi->mmap_length,
             (u32)&__kernel_start, (u32)&__kernel_end);
    console_printf("PMM: total=%u frames free=%u frames\n",
                   pmm_total_frames(), pmm_free_frames());
    gdt_init();
    console_write("GDT installed (kernel 0x08/0x10, user 0x18/0x20, TSS 0x28)\n");
    vmm_init();
    console_write("Paging enabled (kernel identity-mapped 0-32 MB)\n");
    /* Framebuffer: after paging, so its physical pages can be mapped.
       v0.7.1: if GRUB did not set a graphics mode (the Bochs
       failure: kernel booted in text mode, `gui` said "no
       framebuffer"), try the Bochs VBE fallback before giving up.
       If the mapped framebuffer does not read back a test pixel,
       drop to text mode rather than drawing into a broken
       framebuffer. */
    int fb_source = 0; /* 1 = Multiboot, 2 = VBE fallback */
    if (fb_present == 0) fb_source = 1;
    else {
        /* Keep the Multiboot failure reason visible: fb_vbe_try
           overwrites diag_reason with its own reason, and without
           this line a Bochs boot log could not tell whether GRUB
           failed to set a mode or the VBE fallback failed. */
        console_printf("Multiboot framebuffer: %s (bpp=%d type=%d)\n",
                       fb_parse_reason(), fb_diag_bpp(), fb_diag_type());
        if (fb_vbe_try() == 0) fb_source = 2;
    }
    if (fb_source != 0 && fb_init() == 0 && fb_verify() == 0) {
        console_printf("Framebuffer: %ux%u, pitch %u, phys 0x%x (%s)\n",
                       fb_width(), fb_height(), fb_pitch(), fb_phys_addr(),
                       fb_source == 1 ? "Multiboot" : "VBE fallback");
        console_switch_to_fb();
    } else {
        if (fb_source != 0) fb_disable();
        if (fb_source == 2) fb_vbe_disable();
        console_printf("Framebuffer: not available (text mode) - %s\n", fb_diag_reason());
    }
    idt_init();
    pic_init();
    pit_init();
    keyboard_init();
    if (mouse_init()) console_write("Mouse: PS/2 mouse detected\n");
    else console_write("Mouse: not detected (GUI cursor will not move)\n");
    /* v0.7.3: drain once more after mouse_init, so a mouse byte
       left behind by its ACK exchange cannot lodge in the 1-byte
       output buffer and block the keyboard. The total drained at
       startup is reported at the first shell prompt (see shell),
       so a user can tell whether lodged bytes were the problem. */
    (void)keyboard_drain_controller();
    __asm__ volatile ("sti");
    console_write("Interrupts enabled\n");
    /* Network: NIC init must not fail the boot (a VM without a
       NIC still boots to the shell; net commands report it). */
    if (net_init() == 0) console_write("Network: e1000 ready (run dhcp)\n");
    else console_write("Network: no NIC, net commands will report this\n");
    /* Disk encryption unlock, before any filesystem access: an
       encrypted disk needs its passphrase first, or the filesystem
       mount would read ciphertext as a superblock. Unencrypted
       disks and no disk return immediately, with no prompt. */
    if (enc_unlock() != 0)
        console_write("Disk encryption: header invalid, disk will not mount\n");
    else if (enc_enabled())
        console_write("Disk encryption: AES-256-CTR enabled\n");
    int fs_rc = fs_mount();
    if (fs_rc == 0) {
        console_write("Filesystem mounted\n");
        fs_status();
    } else if (fs_rc == -1) {
        console_write("Filesystem: no disk attached (fs commands will report this)\n");
    } else {
        console_write("Filesystem: disk has no valid nxtsFS (not formatted by kernel)\n");
    }
    console_write("Starting built-in test programs (2 processes)...\n");
    console_write("The nxts> shell prompt will appear when they finish; keys typed now are buffered.\n");
    proc_init();
    scheduler_run();
    console_write("Test programs finished. Starting shell...\n");
    shell_run();
    panic("shell returned");
}
