#!/usr/bin/env python3
"""Boot nxtsOS's kernel under Unicorn (x86 CPU emulator, NOT QEMU).

Loads the ELF LOAD segments at their physical addresses, sets up a GDT
and a fake Multiboot info block (as GRUB would), captures COM1 serial
output via OUT-port hooks, and stops when the shell prompt appears.
This verifies the kernel's boot path, console, PMM, IDT/PIC/PIT setup
and shell entry -- it does NOT verify real hardware interrupts, VGA
display, or keyboard input, which need QEMU (see tests/qemu_test.py).

Usage: python3 tests/unicorn_boot.py [path/to/nxtsOS.bin]
Exit 0 only if the prompt and the boot markers are in the serial log.
"""
import struct, sys
from unicorn import *
from unicorn.x86_const import *

BIN = sys.argv[1] if len(sys.argv) > 1 else "build/nxtsOS.bin"
data = open(BIN, "rb").read()

def gdt_entry(base, limit, access, flags):
    return struct.pack("<HB BHBB", limit & 0xFFFF, base & 0xFFFF,
                       (base >> 16) & 0xFF, access,
                       ((limit >> 16) & 0xF) | (flags << 4), (base >> 24) & 0xFF)

uc = Uc(UC_ARCH_X86, UC_MODE_32)
uc.mem_map(0x0, 0x2000000)  # 32 MiB: low memory, kernel at 1 MiB, VGA, stack

# ELF LOAD segments -> physical addresses
e_phoff = struct.unpack_from("<I", data, 28)[0]
e_phentsize, e_phnum = struct.unpack_from("<HH", data, 42)
entry = struct.unpack_from("<I", data, 24)[0]
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
        struct.unpack_from("<IIIIIIII", data, off)
    if p_type != 1:  # PT_LOAD only
        continue
    uc.mem_write(p_paddr, data[p_offset:p_offset + p_filesz])
    if p_memsz > p_filesz:
        uc.mem_write(p_paddr + p_filesz, b"\x00" * (p_memsz - p_filesz))

# Unicorn's default 32-bit segments are already flat (base 0, 4 GiB),
# which is all this kernel needs before any interrupt fires: boot.S and
# kmain never reload segment registers, and no IRQ is injected here.
# (A GDT is still written at 0x1000 for reference, but is not loaded.)
gdt = b"\x00" * 8 + gdt_entry(0, 0xFFFFF, 0x9A, 0xC) + gdt_entry(0, 0xFFFFF, 0x92, 0xC)
uc.mem_write(0x1000, gdt)
uc.reg_write(UC_X86_REG_EFLAGS, 0x2)

# Fake Multiboot info at 0x2000, memory map at 0x3000.
MBI = 0x2000
mmap = b""
for addr, length, typ in ((0x0, 0x9FC00, 1), (0x100000, 0x7F00000, 1)):
    mmap += struct.pack("<I II I", 20, addr, 0, length, 0, typ) if False else \
        struct.pack("<I", 20) + struct.pack("<II", addr, 0) + \
        struct.pack("<II", length, 0) + struct.pack("<I", typ)
uc.mem_write(0x3000, mmap)
mbi = bytearray(52)
struct.pack_into("<I", mbi, 4, 640)      # mem_lower (KiB)
struct.pack_into("<I", mbi, 8, 130048)   # mem_upper (KiB, 128 MiB total)
struct.pack_into("<I", mbi, 44, len(mmap))
struct.pack_into("<I", mbi, 48, 0x3000)
uc.mem_write(MBI, bytes(mbi))

out = []
dlab = [False]
def hook_out(uc, port, size, value, user):
    if port == 0x3FB:  # COM1 line control: bit 7 = divisor-latch access
        dlab[0] = bool(value & 0x80)
        return
    if port == 0x3F8 and not dlab[0]:  # COM1 data (not divisor latch)
        out.append(chr(value & 0xFF))
        if "".join(out).endswith("nxts> "):
            uc.emu_stop()
    # all other OUT ports (PIC, PIT, VGA cursor): accepted, ignored
def hook_in(uc, port, size, user):
    if port == 0x3FD:  # COM1 line status: transmitter empty
        return 0x20
    return 0
uc.hook_add(UC_HOOK_INSN, hook_out, None, 1, 0, UC_X86_INS_OUT)
uc.hook_add(UC_HOOK_INSN, hook_in, None, 1, 0, UC_X86_INS_IN)

uc.reg_write(UC_X86_REG_EAX, 0x2BADB002)
uc.reg_write(UC_X86_REG_EBX, MBI)
try:
    uc.emu_start(entry, entry + 0x10000, timeout=10 * 1000000, count=20_000_000)
except UcError as e:
    print("Unicorn error:", e)
log = "".join(out)
print("--- serial log (Unicorn) ---")
print(log)
print("--- marker check ---")
ok = True
for m in ("nxtsOS kernel starting", "PMM:", "Interrupts enabled", "nxts> "):
    found = m in log
    print(f"{'FOUND' if found else 'MISSING'}: {m}")
    ok = ok and found
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
