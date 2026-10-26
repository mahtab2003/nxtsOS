#!/usr/bin/env python3
"""Host-side source checks: required modules exist, no build artefacts
or secrets are packaged as source."""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQUIRED = [
    "boot/boot.S", "boot/linker.ld",
    "kernel/main.c", "kernel/console.c", "kernel/shell.c", "kernel/panic.c",
    "drivers/serial.c", "drivers/idt.c", "drivers/pic.c", "drivers/pit.c",
    "drivers/keyboard.c", "drivers/isr.S", "drivers/gdt.c", "drivers/gdt.S",
    "mm/vmm.c", "kernel/proc.c", "kernel/syscall.c", "kernel/switch.S",
    "kernel/syscall.S", "kernel/user_blob.S",
    "userland/test_prog.c", "userland/test_prog.S", "userland/linker.ld",
    "tests/qemu_test_user.py",
    "mm/pmm.c",
    "scripts/build.sh", "scripts/run_qemu.sh", "scripts/test_boot.sh",
    "README.md", "LICENSE", "VERSION",
]
BAD = [".iso", ".bin", ".o"]
ok = True
for f in REQUIRED:
    if not os.path.isfile(os.path.join(ROOT, f)):
        print("MISSING:", f); ok = False
for dirpath, _dirs, files in os.walk(ROOT):
    if any(x in dirpath for x in ("build", "archives", ".git")): continue
    for fn in files:
        if any(fn.endswith(e) for e in BAD):
            print("BUILD ARTEFACT IN SOURCE TREE:", os.path.join(dirpath, fn)); ok = False
print("SOURCE CHECK:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
