#!/bin/sh
# Windowed QEMU run. Usage: ./scripts/run_qemu.sh [RAM_MB, default 128]
set -e
cd "$(dirname "$0")/.."
RAM="${1:-128}"
mkdir -p logs
exec qemu-system-x86_64 -cdrom build/nxtsOS.iso -boot d -m "$RAM" \
    -serial "file:logs/serial.log" -display default
