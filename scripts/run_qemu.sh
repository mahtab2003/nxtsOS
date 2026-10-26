#!/bin/sh
# Windowed QEMU run. Usage: ./scripts/run_qemu.sh [RAM_MB, default 128]
set -e
cd "$(dirname "$0")/.."
RAM="${1:-128}"
mkdir -p logs
if [ -f build/nxtsOS-disk.img ]; then
    DRIVE="-drive file=build/nxtsOS-disk.img,format=raw,if=ide,index=0"
else
    DRIVE=""
fi
# shellcheck disable=SC2086
exec qemu-system-x86_64 -cdrom build/nxtsOS.iso -boot d -m "$RAM" $DRIVE \
    -serial "file:logs/serial.log" -display default
