#include "acpi.h"
#include "../mm/vmm.h"

/* Scratch window for reading ACPI tables that live above the
   32 MiB identity-mapped region. The window sits at 32 MiB
   (PD index 8, never mapped by vmm_init and never shared into
   user page directories), one page at a time, with an invlpg
   after each remap. The page-table frame comes from
   pmm_alloc_frame, which scans from frame 0 upward, so it is
   a low frame in practice; vmm_map_page would panic otherwise,
   and that path is already exercised at runtime by
   vmm_map_user. Table parsing runs synchronously in the shell
   (kernel PD active, no scheduler switch mid-parse). */
#define ACPI_WIN 0x02000000u
static u32 acpi_win_page = 0xFFFFFFFFu;

static u8 acpi_read_byte(u32 phys) {
    /* Page 0 is deliberately unmapped (null dereferences must
       fault), so the EBDA pointer at 0x40E cannot be read
       directly either — it goes through the window like any
       address outside the identity map. */
    if (phys >= 4096 && phys < KERNEL_MAP_END) return *(volatile u8 *)phys;
    u32 page = phys & ~0xFFFu;
    if (page != acpi_win_page) {
        vmm_map_page(vmm_kernel_pd(), ACPI_WIN, page, PAGE_RW);
        __asm__ volatile ("invlpg (%0)" :: "r"(ACPI_WIN) : "memory");
        acpi_win_page = page;
    }
    return *(volatile u8 *)(ACPI_WIN + (phys & 0xFFFu));
}

static u32 acpi_read_u32(u32 phys) {
    u32 v = 0;
    for (int i = 0; i < 4; i++)
        v |= (u32)acpi_read_byte(phys + (u32)i) << (i * 8);
    return v;
}

static int acpi_sig(u32 phys, const char *sig4) {
    for (int i = 0; i < 4; i++)
        if (acpi_read_byte(phys + (u32)i) != (u8)sig4[i]) return 0;
    return 1;
}

static int acpi_checksum(u32 phys, u32 len) {
    u32 sum = 0;
    for (u32 i = 0; i < len; i++) sum += acpi_read_byte(phys + i);
    return (sum & 0xFFu) == 0;
}

static int acpi_sig8(u32 phys, const char *sig8) {
    for (int i = 0; i < 8; i++)
        if (acpi_read_byte(phys + (u32)i) != (u8)sig8[i]) return 0;
    return 1;
}

/* Parsed state, cached after the first acpi_init(). */
static int acpi_state = -1; /* -1 unknown, 0 unavailable, 1 ready */
static const char *acpi_fail_stage = "not started";
static u32 acpi_rsdp = 0, acpi_rsdt = 0, acpi_fadt = 0;
static u32 acpi_smi_cmd = 0, acpi_enable_val = 0;
static u32 acpi_pm1a = 0, acpi_pm1b = 0;
static u32 acpi_slp_typa = 0, acpi_slp_typb = 0;

/* Parse the _S5 package out of the DSDT: find the "_S5_" name,
   expect a PackageOp (0x12) next, skip the PkgLength encoding,
   read NumElements, then up to 2 element values (Byte/Word/
   DWord/Zero/One prefixes). Returns 0 on success. A structural
   failure at one candidate offset returns -1 so the caller can
   keep scanning: a false "_S5_" byte pattern inside a data blob
   must not abort the search. */
static int acpi_parse_s5_at(u32 dsdt, u32 dsdt_len, u32 off) {
    /* NameOp payload: the byte after "_S5_" must be PackageOp. */
    if (acpi_read_byte(dsdt + off + 4) != 0x12) return -1;
    u32 pos = off + 5;
    /* PkgLength: bits 6-7 of the first byte = count of
       following length bytes (0-3). */
    u8 b0 = acpi_read_byte(dsdt + pos);
    u32 follow = (b0 >> 6) & 3u;
    pos += 1 + follow;
    if (pos >= dsdt + dsdt_len) return -1;
    u32 n = acpi_read_byte(dsdt + pos);
    pos++;
    if (n < 1) return -1;
    u32 vals[2];
    u32 got = 0;
    for (u32 i = 0; i < n && got < 2; i++) {
        if (pos >= dsdt + dsdt_len) return -1;
        u8 tag = acpi_read_byte(dsdt + pos);
        pos++;
        u32 v = 0;
        if (tag == 0x0A) { /* BytePrefix */
            if (pos >= dsdt + dsdt_len) return -1;
            v = acpi_read_byte(dsdt + pos); pos++;
        } else if (tag == 0x0B) { /* WordPrefix */
            if (pos + 1 >= dsdt + dsdt_len) return -1;
            v = acpi_read_byte(dsdt + pos) |
                ((u32)acpi_read_byte(dsdt + pos + 1) << 8);
            pos += 2;
        } else if (tag == 0x0C) { /* DWordPrefix */
            if (pos + 3 >= dsdt + dsdt_len) return -1;
            v = acpi_read_u32(dsdt + pos);
            pos += 4;
        } else if (tag == 0x00) { /* ZeroOp */
            v = 0;
        } else if (tag == 0x01) { /* OneOp */
            v = 1;
        } else {
            return -1; /* unexpected element encoding */
        }
        vals[got++] = v;
    }
    if (got < 1) return -1;
    if (vals[0] >= 8) return -1; /* SLP_TYP is 3 bits */
    u32 typb = (got >= 2) ? vals[1] : vals[0];
    if (typb >= 8) return -1;
    acpi_slp_typa = vals[0];
    acpi_slp_typb = typb;
    return 0;
}

static int acpi_parse_s5(u32 dsdt, u32 dsdt_len) {
    if (dsdt_len < 36 + 8) return -1;
    for (u32 off = 36; off + 8 <= dsdt_len; off++) {
        if (!acpi_sig(dsdt + off, "_S5_")) continue;
        if (acpi_parse_s5_at(dsdt, dsdt_len, off) == 0) return 0;
    }
    return -1;
}

int acpi_init(void) {
    if (acpi_state >= 0) return acpi_state == 1 ? 0 : -1;
    acpi_state = 0; /* fail-closed default; set to 1 only at the end */
    /* 1. Find the RSDP: EBDA first, then the BIOS ROM area. */
    u32 rsdp = 0;
    /* EBDA pointer at 0x40E: read through the window helper,
       never dereferenced directly (page 0 is unmapped). */
    u16 ebda_seg = (u16)(acpi_read_byte(0x40E) |
                         ((u32)acpi_read_byte(0x40F) << 8));
    u32 ebda = (u32)ebda_seg << 4;
    if (ebda >= 0x40000 && ebda < 0xA0000) {
        for (u32 p = ebda; p < ebda + 1024; p += 16) {
            if (acpi_sig8(p, "RSD PTR ")) { rsdp = p; break; }
        }
    }
    if (!rsdp) {
        for (u32 p = 0xE0000; p < 0x100000; p += 16) {
            if (acpi_sig8(p, "RSD PTR ")) { rsdp = p; break; }
        }
    }
    if (!rsdp) { acpi_fail_stage = "no RSDP"; return -1; }
    acpi_rsdp = rsdp;
    if (!acpi_checksum(rsdp, 20)) { acpi_fail_stage = "bad RSDP checksum"; return -1; }
    /* RSDT only (XSDT ignored by design: SeaBIOS/QEMU always
       provide an RSDT, and 32-bit entries keep this code free
       of u64 address handling). */
    u32 rsdt = acpi_read_u32(rsdp + 16);
    if (!rsdt || !acpi_sig(rsdt, "RSDT")) { acpi_fail_stage = "no RSDT"; return -1; }
    acpi_rsdt = rsdt;
    u32 rsdt_len = acpi_read_u32(rsdt + 4);
    if (rsdt_len < 36 || rsdt_len > 65536) { acpi_fail_stage = "bad RSDT length"; return -1; }
    if (!acpi_checksum(rsdt, rsdt_len)) { acpi_fail_stage = "bad RSDT checksum"; return -1; }
    /* 2. Walk the RSDT for the FADT. */
    u32 fadt = 0;
    for (u32 e = 36; e + 4 <= rsdt_len; e += 4) {
        u32 tab = acpi_read_u32(rsdt + e);
        if (tab && acpi_sig(tab, "FACP")) { fadt = tab; break; }
    }
    if (!fadt) { acpi_fail_stage = "no FADT"; return -1; }
    acpi_fadt = fadt;
    u32 fadt_len = acpi_read_u32(fadt + 4);
    if (fadt_len < 72) { acpi_fail_stage = "bad FADT length"; return -1; }
    if (!acpi_checksum(fadt, fadt_len)) { acpi_fail_stage = "bad FADT checksum"; return -1; }
    acpi_smi_cmd = acpi_read_u32(fadt + 48);
    acpi_enable_val = acpi_read_byte(fadt + 52);
    /* FADT layout (ACPI spec): PM1a_EVT_BLK at 56, PM1b_EVT_BLK
       at 60, PM1a_CNT_BLK at 64, PM1b_CNT_BLK at 68. The CNT
       block — not the EVT block — is the poweroff register.
       (An earlier revision read 56/60 and wrote to the EVT
       status register, which silently did nothing; proven by
       QEMU's own `info mtree`: evt 0x600, cnt 0x604, tmr 0x608.) */
    acpi_pm1a = acpi_read_u32(fadt + 64);
    acpi_pm1b = acpi_read_u32(fadt + 68);
    u32 dsdt = acpi_read_u32(fadt + 40);
    if (!acpi_pm1a) { acpi_fail_stage = "no PM1a block"; return -1; }
    /* 3. DSDT _S5 package for the SLP_TYP values. */
    if (!dsdt || !acpi_sig(dsdt, "DSDT")) { acpi_fail_stage = "no DSDT"; return -1; }
    u32 dsdt_len = acpi_read_u32(dsdt + 4);
    if (dsdt_len < 36 || dsdt_len > 1048576) { acpi_fail_stage = "bad DSDT length"; return -1; }
    if (!acpi_checksum(dsdt, dsdt_len)) { acpi_fail_stage = "bad DSDT checksum"; return -1; }
    if (acpi_parse_s5(dsdt, dsdt_len) != 0) { acpi_fail_stage = "no _S5 package"; return -1; }
    acpi_state = 1;
    return 0;
}

int acpi_available(void) {
    return acpi_init() == 0;
}

void acpi_diag(void) {
    if (acpi_init() != 0) {
        console_printf("ACPI: poweroff unavailable (%s)\n", acpi_fail_stage);
        return;
    }
    console_printf("ACPI: RSDP 0x%x RSDT 0x%x FADT 0x%x\n",
                   acpi_rsdp, acpi_rsdt, acpi_fadt);
    console_printf("ACPI: PM1a 0x%x PM1b 0x%x SLP_TYP %u/%u PM1a_CNT 0x%x\n",
                   acpi_pm1a, acpi_pm1b, acpi_slp_typa, acpi_slp_typb,
                   (u32)inw((u16)acpi_pm1a));
}

int acpi_poweroff(void) {
    if (acpi_init() != 0) return -1;
    /* Enable ACPI mode if the firmware left SCI_EN clear and
       an SMI command port exists. SeaBIOS normally enables it
       at boot, so this is usually a no-op. */
    if (acpi_smi_cmd != 0) {
        if ((inw((u16)acpi_pm1a) & 1) == 0) {
            outb((u16)acpi_smi_cmd, (u8)acpi_enable_val);
            u32 i = 0;
            while (((inw((u16)acpi_pm1a) & 1) == 0) && i < 1000000) i++;
            if ((inw((u16)acpi_pm1a) & 1) == 0) return -1;
        }
    }
    outw((u16)acpi_pm1a, (u16)((acpi_slp_typa << 10) | 0x2000));
    if (acpi_pm1b)
        outw((u16)acpi_pm1b, (u16)((acpi_slp_typb << 10) | 0x2000));
    for (;;) __asm__ volatile ("hlt");
}
