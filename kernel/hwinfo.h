#ifndef NXTS_HWINFO_H
#define NXTS_HWINFO_H
#include "common.h"

/* Hardware information (core CLI family (a)). All values are read
   live from the machine; nothing here is persisted, and no value is
   fabricated when the hardware does not report it. */

/* CPUID. Returns 1 if the CPUID instruction is usable (EFLAGS ID bit
   toggles), 0 otherwise — executing CPUID on a CPU without it would
   raise #UD, so callers must check first. */
int  hw_cpuid_supported(void);
/* 12-char vendor string + NUL (leaf 0, EBX/EDX/ECX order). Empty
   string when CPUID is unavailable. */
void hw_cpu_vendor(char *out);
/* 48-char brand string + NUL, trailing spaces trimmed. Empty when
   the extended leaves are absent or CPUID is unavailable. */
void hw_cpu_brand(char *out);
/* Leaf 1 EAX decoding: family/model with extended-field rules
   applied (family 15 adds ext family; model adds ext model for
   families 6 and 15). All outputs 0 when CPUID is unavailable. */
void hw_cpu_family_model(u32 *family, u32 *model, u32 *stepping);
/* Leaf 1 feature registers, raw. 0 when CPUID is unavailable. */
void hw_cpu_features(u32 *ecx_out, u32 *edx_out);
/* NX bit from extended leaf 0x80000001 EDX bit 20 (1 = present,
   0 = absent or extended leaves unavailable). */
int  hw_cpu_nx(void);

/* PCI bus 0 enumeration. The callback fires once per present
   function, in device/function order. Returns the device count.
   Config access uses the 0xCF8/0xCFC port pair, the same pattern
   fb.c and e1000.c already use for their own devices; this module
   does not touch those drivers' devices, it only reads config
   space. Only bus 0 is scanned: QEMU/Bochs place every device
   there, and bridge-walking is a later phase, not a hidden
   half-finished one. */
typedef void (*hw_pci_cb)(u8 dev, u8 func, u16 vendor, u16 device,
                          u8 class_code, u8 subclass, u8 prog_if, u32 bar0);
int  hw_pci_scan(hw_pci_cb cb);

/* CMOS RTC (ports 0x70/0x71, NMI-disable bit set on the index
   write — the same pattern kernel/csprng.c uses for its boot
   seed). Returns 0 on a valid read, -1 on timeout or an
   out-of-range field (fail-closed, never a fabricated date).
   Year is 2000 + the 2-digit register, the QEMU/SeaBIOS
   convention. */
int  hw_rtc_read(u32 *year, u32 *mon, u32 *day,
                 u32 *hour, u32 *min, u32 *sec);

#endif
