#include "hwinfo.h"

/* ---- CPUID ---- */

static void cpuid_raw(u32 leaf, u32 subleaf,
                      u32 *eax, u32 *ebx, u32 *ecx, u32 *edx) {
    u32 a, b, c, d;
    /* -fno-pic build, so EBX as an output is safe. */
    __asm__ volatile ("cpuid"
                      : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                      : "a"(leaf), "c"(subleaf));
    if (eax) *eax = a;
    if (ebx) *ebx = b;
    if (ecx) *ecx = c;
    if (edx) *edx = d;
}

int hw_cpuid_supported(void) {
    u32 e1, e2;
    /* Standard EFLAGS ID-bit test: if bit 21 toggles, CPUID
       exists. The original flags are restored afterwards. */
    __asm__ volatile (
        "pushfl\n\t"
        "popl %0\n\t"
        "movl %0, %1\n\t"
        "xorl $0x200000, %1\n\t"
        "pushl %1\n\t"
        "popfl\n\t"
        "pushfl\n\t"
        "popl %1\n\t"
        "pushl %0\n\t"
        "popfl\n\t"
        : "=r"(e1), "=r"(e2) :: "cc");
    return ((e1 ^ e2) & 0x200000u) ? 1 : 0;
}

void hw_cpu_vendor(char *out) {
    out[0] = 0;
    if (!hw_cpuid_supported()) return;
    u32 eax, ebx, ecx, edx;
    cpuid_raw(0, 0, &eax, &ebx, &ecx, &edx);
    /* Vendor order is EBX, EDX, ECX. */
    memcpy(out, &ebx, 4);
    memcpy(out + 4, &edx, 4);
    memcpy(out + 8, &ecx, 4);
    out[12] = 0;
}

void hw_cpu_brand(char *out) {
    out[0] = 0;
    if (!hw_cpuid_supported()) return;
    u32 max_ext;
    cpuid_raw(0x80000000u, 0, &max_ext, 0, 0, 0);
    if (max_ext < 0x80000004u) return;
    for (u32 i = 0; i < 3; i++) {
        u32 a, b, c, d;
        cpuid_raw(0x80000002u + i, 0, &a, &b, &c, &d);
        memcpy(out + i * 16, &a, 4);
        memcpy(out + i * 16 + 4, &b, 4);
        memcpy(out + i * 16 + 8, &c, 4);
        memcpy(out + i * 16 + 12, &d, 4);
    }
    out[48] = 0;
    /* Trim trailing spaces (brand strings are space-padded). */
    int n = 48;
    while (n > 0 && out[n - 1] == ' ') out[--n] = 0;
}

void hw_cpu_family_model(u32 *family, u32 *model, u32 *stepping) {
    *family = 0; *model = 0; *stepping = 0;
    if (!hw_cpuid_supported()) return;
    u32 eax;
    cpuid_raw(1, 0, &eax, 0, 0, 0);
    u32 step = eax & 0xFu;
    u32 base_model = (eax >> 4) & 0xFu;
    u32 base_family = (eax >> 8) & 0xFu;
    u32 ext_model = (eax >> 16) & 0xFu;
    u32 ext_family = (eax >> 20) & 0xFFu;
    u32 fam = base_family;
    if (fam == 15) fam += ext_family;
    u32 mod = base_model;
    if (base_family == 6 || base_family == 15) mod += (ext_model << 4);
    *family = fam; *model = mod; *stepping = step;
}

void hw_cpu_features(u32 *ecx_out, u32 *edx_out) {
    *ecx_out = 0; *edx_out = 0;
    if (!hw_cpuid_supported()) return;
    u32 ecx, edx;
    cpuid_raw(1, 0, 0, 0, &ecx, &edx);
    *ecx_out = ecx; *edx_out = edx;
}

int hw_cpu_nx(void) {
    if (!hw_cpuid_supported()) return 0;
    u32 max_ext;
    cpuid_raw(0x80000000u, 0, &max_ext, 0, 0, 0);
    if (max_ext < 0x80000001u) return 0;
    u32 edx;
    cpuid_raw(0x80000001u, 0, 0, 0, 0, &edx);
    return (edx & (1u << 20)) ? 1 : 0;
}

/* ---- PCI (bus 0) ---- */

static u32 pci_cfg_read(u8 dev, u8 func, u8 off) {
    u32 addr = 0x80000000u | ((u32)dev << 11) | ((u32)func << 8) | (off & 0xFC);
    outl(0xCF8, addr);
    return inl(0xCFC);
}

int hw_pci_scan(hw_pci_cb cb) {
    int count = 0;
    for (u32 dev = 0; dev < 32; dev++) {
        u32 id = pci_cfg_read((u8)dev, 0, 0);
        if ((id & 0xFFFFu) == 0xFFFFu) continue; /* no device */
        u32 hdr = pci_cfg_read((u8)dev, 0, 0x0E);
        u32 funcs = (hdr & 0x80u) ? 8 : 1;
        for (u32 f = 0; f < funcs; f++) {
            u32 idf = pci_cfg_read((u8)dev, (u8)f, 0);
            if ((idf & 0xFFFFu) == 0xFFFFu) continue;
            u32 classrev = pci_cfg_read((u8)dev, (u8)f, 0x08);
            u32 bar0 = pci_cfg_read((u8)dev, (u8)f, 0x10);
            if (cb) cb((u8)dev, (u8)f, (u16)(idf & 0xFFFFu),
                       (u16)(idf >> 16),
                       (u8)(classrev >> 24), (u8)(classrev >> 16),
                       (u8)(classrev >> 8), bar0);
            count++;
        }
    }
    return count;
}

int hw_pci_scan_detail(hw_pci_detail_cb cb) {
    int count = 0;
    for (u32 dev = 0; dev < 32; dev++) {
        u32 id = pci_cfg_read((u8)dev, 0, 0);
        if ((id & 0xFFFFu) == 0xFFFFu) continue;
        u32 hdr = pci_cfg_read((u8)dev, 0, 0x0E);
        u32 funcs = (hdr & 0x80u) ? 8 : 1;
        for (u32 f = 0; f < funcs; f++) {
            u32 idf = pci_cfg_read((u8)dev, (u8)f, 0);
            if ((idf & 0xFFFFu) == 0xFFFFu) continue;
            u32 classrev = pci_cfg_read((u8)dev, (u8)f, 0x08);
            u32 irq = pci_cfg_read((u8)dev, (u8)f, 0x3C);
            if (cb) cb((u8)dev, (u8)f, (u16)(idf & 0xFFFFu),
                       (u16)(idf >> 16),
                       (u8)(classrev >> 24), (u8)(classrev >> 16),
                       (u8)(classrev >> 8), (u8)(classrev & 0xFFu),
                       pci_cfg_read((u8)dev, (u8)f, 0x10),
                       pci_cfg_read((u8)dev, (u8)f, 0x14),
                       pci_cfg_read((u8)dev, (u8)f, 0x18),
                       pci_cfg_read((u8)dev, (u8)f, 0x1C),
                       pci_cfg_read((u8)dev, (u8)f, 0x20),
                       pci_cfg_read((u8)dev, (u8)f, 0x24),
                       (u8)(irq & 0xFFu));
            count++;
        }
    }
    return count;
}

u32 hw_cpu_count(void) {
    if (!hw_cpuid_supported()) return 1;
    u32 max_leaf = 0, ebx = 0, ecx = 0, edx = 0;
    cpuid_raw(0, 0, &max_leaf, 0, 0, 0);
    if (max_leaf >= 0x0Bu) {
        /* Leaf 0xB, level 0 (SMT) then level 1 (core): EBX is the
           number of logical processors at that level. */
        cpuid_raw(0x0Bu, 1, 0, &ebx, 0, 0);
        if (ebx >= 1) return ebx;
        cpuid_raw(0x0Bu, 0, 0, &ebx, 0, 0);
        if (ebx >= 1) return ebx;
    }
    /* Leaf 1 EBX bits 23:16 = max logical processors (HTT). */
    cpuid_raw(1, 0, 0, &ebx, &ecx, &edx);
    u32 n = (ebx >> 16) & 0xFFu;
    if ((edx & (1u << 28)) && n >= 1) return n;
    return 1;
}

/* ---- CMOS RTC ---- */

static u8 rtc_reg(u8 reg) {
    outb(0x70, (u8)(0x80 | reg));
    return inb(0x71);
}

static u32 bcd_to_dec(u8 v) {
    return (u32)((v >> 4) * 10 + (v & 0x0F));
}

int hw_rtc_read(u32 *year, u32 *mon, u32 *day,
                u32 *hour, u32 *min, u32 *sec) {
    /* Wait out an update-in-progress, bounded: a stuck RTC must
       not hang the shell. */
    for (u32 i = 0; i < 100000; i++) {
        if ((rtc_reg(0x0A) & 0x80) == 0) break;
        if (i == 99999) return -1;
    }
    u8 status_b = rtc_reg(0x0B);
    int binary = (status_b & 0x04) != 0;
    int mode24 = (status_b & 0x02) != 0;
    u8 s = rtc_reg(0x00), m = rtc_reg(0x02), h = rtc_reg(0x04);
    u8 d = rtc_reg(0x07), mo = rtc_reg(0x08), y = rtc_reg(0x09);
    u32 sec_v, min_v, hour_v, day_v, mon_v, year_v;
    if (binary) {
        sec_v = s; min_v = m; hour_v = h & 0x7F; day_v = d; mon_v = mo; year_v = y;
    } else {
        sec_v = bcd_to_dec(s); min_v = bcd_to_dec(m);
        hour_v = bcd_to_dec((u8)(h & 0x7F));
        day_v = bcd_to_dec(d); mon_v = bcd_to_dec(mo); year_v = bcd_to_dec(y);
    }
    if (!mode24) {
        int pm = (h & 0x80) != 0;
        if (pm && hour_v != 12) hour_v += 12;
        if (!pm && hour_v == 12) hour_v = 0;
    }
    if (sec_v > 59 || min_v > 59 || hour_v > 23 ||
        day_v < 1 || day_v > 31 || mon_v < 1 || mon_v > 12) return -1;
    *sec = sec_v; *min = min_v; *hour = hour_v;
    *day = day_v; *mon = mon_v; *year = 2000 + year_v;
    return 0;
}

static void rtc_reg_write(u8 reg, u8 val) {
    outb(0x70, (u8)(0x80 | reg));
    outb(0x71, val);
}

static u8 dec_to_bcd(u32 v) {
    return (u8)(((v / 10) << 4) | (v % 10));
}

/* Write the CMOS RTC (parity run: `date set`). The caller must
   have validated every field already — this function validates
   again and refuses before writing anything (never a partial
   write). Encoding mirrors hw_rtc_read: the write uses the
   RTC's current format (BCD vs binary, 12h vs 24h), the SET
   bit (status B bit 7) freezes updates while the registers
   are written, and update-in-progress is waited out first
   (bounded, fail-closed). Year is 2000 + the 2-digit
   register, the QEMU/SeaBIOS convention. */
int hw_rtc_write(u32 year, u32 mon, u32 day,
                 u32 hour, u32 min, u32 sec) {
    static const u8 mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (year < 2000 || year > 2099 || mon < 1 || mon > 12 ||
        hour > 23 || min > 59 || sec > 59) return -1;
    u32 leap = (year % 4 == 0) ? 1 : 0;
    u32 maxd = mdays[mon - 1] + ((mon == 2) ? leap : 0);
    if (day < 1 || day > maxd) return -1;
    for (u32 i = 0; i < 100000; i++) {
        if ((rtc_reg(0x0A) & 0x80) == 0) break;
        if (i == 99999) return -1;
    }
    u8 status_b = rtc_reg(0x0B);
    int binary = (status_b & 0x04) != 0;
    int mode24 = (status_b & 0x02) != 0;
    u8 h = (u8)hour;
    if (!mode24) {
        if (hour == 0) h = 12;
        else if (hour > 12) { h = (u8)(hour - 12); h |= 0x80; }
        else if (hour == 12) h |= 0x80;
    }
    u8 s = (u8)sec, m = (u8)min, d = (u8)day, mo = (u8)mon, y = (u8)(year - 2000);
    if (!binary) {
        s = dec_to_bcd(sec); m = dec_to_bcd(min);
        d = dec_to_bcd(day); mo = dec_to_bcd(mon); y = dec_to_bcd(year - 2000);
        if (!mode24) {
            u8 hb = dec_to_bcd(h & 0x7F);
            h = (u8)(hb | (h & 0x80));
        }
    }
    rtc_reg_write(0x0B, (u8)(status_b | 0x80));
    rtc_reg_write(0x00, s);
    rtc_reg_write(0x02, m);
    rtc_reg_write(0x04, h);
    rtc_reg_write(0x07, d);
    rtc_reg_write(0x08, mo);
    rtc_reg_write(0x09, y);
    rtc_reg_write(0x0B, status_b);
    return 0;
}
