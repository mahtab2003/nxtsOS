/* Intel 8254x (e1000) driver, QEMU's default NIC (82540EM, PCI
   device 0x100E). Polled, not interrupt-driven: net_poll()
   drains the RX ring. MMIO is mapped UNCACHED (PCD+PWT) —
   cached MMIO reads would return stale register values.
   Descriptor rings and buffers live in kernel .bss, which is
   identity-mapped, so a buffer's virtual address IS its DMA
   physical address. TX is serialised: a send waits for its
   descriptor's DD bit before returning, so callers never
   overwrite an in-flight buffer. */
#include "net.h"
#include "../mm/pmm.h"
#include "../mm/vmm.h"
#include "../drivers/pit.h"

/* PCI config ports. */
static u32 pci_cfg_read(u32 dev, u32 func, u32 off) {
    outl(0xCF8, 0x80000000u | (dev << 11) | (func << 8) | (off & 0xFC));
    return inl(0xCFC);
}
static void pci_cfg_write16(u32 dev, u32 func, u32 off, u16 val) {
    outl(0xCF8, 0x80000000u | (dev << 11) | (func << 8) | (off & 0xFC));
    outw(0xCFC + (off & 2), val);
}

/* e1000 MMIO registers (8254x datasheet). */
#define REG_CTRL   0x0000
#define REG_STATUS 0x0008
#define REG_EERD   0x0014
#define REG_RCTL   0x0100
#define REG_TCTL   0x0400
#define REG_TIPG   0x0410
#define REG_IMS    0x00D0
/* Datasheet offsets (8254x): base-low/high, then length, then
   head, then tail. An earlier version of this file had base
   and length swapped (0x2808/0x3808 are the LENGTH registers,
   not the base registers): the ring address went into RDLEN/
   TDLEN and the length (512/128) went into RDBAL/TDBAL, so
   QEMU read descriptors from physical 0x200/0x80 — empty
   memory — advanced TDH past them, and sent nothing. The
   netdbg readback (TDBAL reading 0x8FB00, i.e. the length
   register masked to 20 bits) exposed the swap. */
#define REG_RDBAL  0x2800
#define REG_RDBAH  0x2804
#define REG_RDLEN  0x2808
#define REG_RDH    0x2810
#define REG_RDT    0x2818
#define REG_TDBAL  0x3800
#define REG_TDBAH  0x3804
#define REG_TDLEN  0x3808
#define REG_TDH    0x3810
#define REG_TDT    0x3818
#define REG_RAL    0x5400
#define REG_RAH    0x5404
#define REG_MTA    0x5200

#define NET_MMIO_VIRT 0x41000000u
#define PAGE_PCD 0x10u
#define PAGE_PWT 0x08u

#define RX_COUNT 32
#define TX_COUNT 8
#define BUF_SIZE 2048

struct rx_desc {
    u32 addr_lo, addr_hi;
    u16 length, checksum;
    u8 status, errors;
    u16 special;
} __attribute__((packed));
struct tx_desc {
    u32 addr_lo, addr_hi;
    u16 length;
    u8 cso, cmd, status, css;
    u16 special;
} __attribute__((packed));

static volatile u32 *mmio = 0;
static struct rx_desc rx_ring[RX_COUNT] __attribute__((aligned(128)));
static struct tx_desc tx_ring[TX_COUNT] __attribute__((aligned(128)));
static u8 rx_bufs[RX_COUNT][BUF_SIZE] __attribute__((aligned(16)));
static u8 tx_bufs[TX_COUNT][BUF_SIZE] __attribute__((aligned(16)));
static int rx_cur = 0;
static int tx_cur = 0;
static int present = 0;
static mac_t our_mac;
static u32 rx_count = 0, tx_count = 0, drop_count = 0;

static u32 mmio_read(u32 reg) { return mmio[reg / 4]; }
static void mmio_write(u32 reg, u32 val) { mmio[reg / 4] = val; }

int net_present(void) { return present; }
void net_dbg(void) {
    if (!present) { console_write("netdbg: no NIC\n"); return; }
    console_printf("netdbg: STATUS 0x%x TDH %u TDT %u RDH %u RDT %u\n",
                   mmio_read(REG_STATUS), mmio_read(REG_TDH), mmio_read(REG_TDT),
                   mmio_read(REG_RDH), mmio_read(REG_RDT));
    console_printf("netdbg: tx0 addr 0x%x len %u cmd 0x%x status 0x%x\n",
                   tx_ring[0].addr_lo, tx_ring[0].length, tx_ring[0].cmd, tx_ring[0].status);
    console_printf("netdbg: tx_ring 0x%x TDBAL 0x%x rx_ring 0x%x RDBAL 0x%x\n",
                   (u32)tx_ring, mmio_read(REG_TDBAL), (u32)rx_ring, mmio_read(REG_RDBAL));
    console_printf("netdbg: rx0 addr 0x%x len %u status 0x%x\n",
                   rx_ring[0].addr_lo, rx_ring[0].length, rx_ring[0].status);
}
void net_mac(mac_t *out) { memcpy(out->b, our_mac.b, 6); }
u32 net_rx_count(void) { return rx_count; }
u32 net_tx_count(void) { return tx_count; }
u32 net_drop_count(void) { return drop_count; }

int net_init(void) {
    /* Scan PCI bus 0 for an Intel e1000-family Ethernet device. */
    u32 found_dev = 0, found_bar = 0, found_id = 0;
    for (u32 dev = 0; dev < 32 && !found_bar; dev++) {
        u32 id = pci_cfg_read(dev, 0, 0);
        if (id == 0xFFFFFFFFu) continue;
        u32 vendor = id & 0xFFFF, device = id >> 16;
        u32 cls = pci_cfg_read(dev, 0, 0x08);
        u32 class_code = (cls >> 24) & 0xFF; /* byte 0x0B */
        if (vendor != 0x8086 || class_code != 0x02) continue;
        /* e1000 family device IDs (QEMU uses 0x100E). */
        if (device != 0x100E && device != 0x100F && device != 0x1010 &&
            device != 0x1017 && device != 0x1008 && device != 0x1011) continue;
        u32 bar = pci_cfg_read(dev, 0, 0x10);
        if (bar & 1) continue; /* IO BAR, not MMIO */
        bar &= ~0xFu;
        if (bar == 0) continue;
        found_dev = dev; found_bar = bar; found_id = device;
        /* Enable memory space + bus mastering. */
        u32 cmd = pci_cfg_read(dev, 0, 0x04) & 0xFFFF;
        pci_cfg_write16(dev, 0, 0x04, (u16)(cmd | 0x0007));
    }
    if (!found_bar) {
        console_write("net: no e1000 NIC found on PCI bus 0\n");
        return -1;
    }
    console_printf("net: e1000 device 0x%x BAR0 0x%x\n", found_id, found_bar);
    /* Map 128 KiB of MMIO, uncached. */
    for (int i = 0; i < 32; i++)
        vmm_map_page(vmm_kernel_pd(), NET_MMIO_VIRT + (u32)i * 4096,
                     found_bar + (u32)i * 4096, PAGE_RW | PAGE_PCD | PAGE_PWT);
    vmm_enable_paging(vmm_kernel_pd()); /* flush TLB */
    mmio = (volatile u32 *)NET_MMIO_VIRT;
    /* Reset: CTRL.RST (bit 26), then wait for it to clear. */
    mmio_write(REG_CTRL, mmio_read(REG_CTRL) | (1u << 26));
    u32 start = timer_ticks;
    while ((mmio_read(REG_CTRL) & (1u << 26)) && timer_ticks - start < 100) { }
    /* Link up: SLU (bit 6) + ASDE (bit 5) + full duplex (bit 0). */
    mmio_write(REG_CTRL, (1u << 0) | (1u << 5) | (1u << 6));
    /* Clear multicast table. */
    for (int i = 0; i < 128; i++) mmio_write(REG_MTA + (u32)i * 4, 0);
    /* No interrupts: polling only. */
    mmio_write(REG_IMS, 0);
    /* MAC address from RAL/RAH (QEMU presets them). */
    u32 ral = mmio_read(REG_RAL), rah = mmio_read(REG_RAH);
    if (ral == 0 && rah == 0) {
        console_write("net: e1000 has no MAC in RAL/RAH, giving up\n");
        return -1;
    }
    our_mac.b[0] = (u8)ral; our_mac.b[1] = (u8)(ral >> 8);
    our_mac.b[2] = (u8)(ral >> 16); our_mac.b[3] = (u8)(ral >> 24);
    our_mac.b[4] = (u8)rah; our_mac.b[5] = (u8)(rah >> 8);
    console_printf("net: MAC %x:%x:%x:%x:%x:%x\n", our_mac.b[0], our_mac.b[1],
                   our_mac.b[2], our_mac.b[3], our_mac.b[4], our_mac.b[5]);
    /* RX ring. */
    memset(rx_ring, 0, sizeof(rx_ring));
    for (int i = 0; i < RX_COUNT; i++) {
        rx_ring[i].addr_lo = (u32)rx_bufs[i];
        rx_ring[i].addr_hi = 0;
        rx_ring[i].status = 0;
    }
    mmio_write(REG_RDBAL, (u32)rx_ring);
    mmio_write(REG_RDBAH, 0);
    mmio_write(REG_RDLEN, RX_COUNT * 16);
    mmio_write(REG_RDH, 0);
    mmio_write(REG_RDT, RX_COUNT - 1);
    /* RCTL: EN (bit 1) | BAM (bit 15) | SECRC strip (bit 26).
       BSIZE field 0 = 2048-byte buffers. */
    mmio_write(REG_RCTL, (1u << 1) | (1u << 15) | (1u << 26));
    /* TX ring. */
    memset(tx_ring, 0, sizeof(tx_ring));
    for (int i = 0; i < TX_COUNT; i++) {
        tx_ring[i].addr_lo = (u32)tx_bufs[i];
        tx_ring[i].addr_hi = 0;
    }
    mmio_write(REG_TDBAL, (u32)tx_ring);
    mmio_write(REG_TDBAH, 0);
    mmio_write(REG_TDLEN, TX_COUNT * 16);
    mmio_write(REG_TDH, 0);
    mmio_write(REG_TDT, 0);
    /* TCTL: EN (bit 1) | PSP (bit 3). TIPG: 10/10/10. */
    mmio_write(REG_TCTL, (1u << 1) | (1u << 3));
    mmio_write(REG_TIPG, 10 | (10u << 10) | (10u << 20));
    present = 1;
    u32 st = mmio_read(REG_STATUS);
    console_printf("net: link %s (STATUS 0x%x)\n", (st & 2) ? "up" : "down", st);
    (void)found_dev;
    return 0;
}

int net_send(const u8 *frame, u32 len) {
    if (!present) return -1;
    if (len < 14 || len > 1518) { drop_count++; return -1; }
    int slot = tx_cur;
    /* No pre-wait needed: sends are serialised (each send waits
       for TDH/DD completion below before returning), so a slot
       is never rewritten while the hardware still owns it. */
    u32 start = timer_ticks;
    memcpy(tx_bufs[slot], frame, len);
    tx_ring[slot].addr_lo = (u32)tx_bufs[slot];
    tx_ring[slot].addr_hi = 0;
    tx_ring[slot].length = (u16)len;
    tx_ring[slot].cso = 0;
    tx_ring[slot].cmd = 0x01 | 0x02 | 0x08; /* EOP | IFCS | RS */
    tx_ring[slot].status = 0;
    tx_ring[slot].css = 0;
    tx_ring[slot].special = 0;
    /* TDT points PAST the last valid descriptor (the next free
       slot): the hardware fetches descriptors from TDH up to
       TDT. */
    u32 tdh_before = mmio_read(REG_TDH);
    mmio_write(REG_TDT, (u32)((slot + 1) % TX_COUNT));
    /* Completion: TDH advancing past this slot means the
       hardware processed (transmitted) it — this is the signal
       Linux's e1000 driver uses to reclaim descriptors. The
       DD status bit is also accepted. (Observed in QEMU:
       TDH advanced 0 -> 1 for the DHCP discover, but DD was
       never written back, so waiting on DD alone deadlocked
       every send. TDH advancement is the reliable signal.) */
    start = timer_ticks;
    while (mmio_read(REG_TDH) != (u32)((slot + 1) % TX_COUNT) &&
           (tx_ring[slot].status & 0x01) == 0) {
        if (timer_ticks - start > 100) { drop_count++; return -1; }
    }
    tx_cur = (slot + 1) % TX_COUNT;
    tx_count++;
    return 0;
}

void net_poll(void) {
    if (!present) return;
    int processed = 0;
    while (rx_ring[rx_cur].status & 0x01) {
        struct rx_desc *d = &rx_ring[rx_cur];
        u32 len = d->length;
        u8 status = d->status;
        if ((status & 0x02) && len >= 14 && len <= BUF_SIZE) {
            rx_count++;
            net_rx_frame(rx_bufs[rx_cur], len);
        } else {
            drop_count++; /* not EOP, or length out of range */
        }
        d->status = 0;
        rx_cur = (rx_cur + 1) % RX_COUNT;
        processed = 1;
    }
    if (processed)
        mmio_write(REG_RDT, (u32)((rx_cur - 1 + RX_COUNT) % RX_COUNT));
}
