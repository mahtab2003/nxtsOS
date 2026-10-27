#!/bin/sh
# QEMU boot test (128 MB, windowless, monitor-typed shell commands).
set -e
cd "$(dirname "$0")/.."
mkdir -p logs
python3 tests/qemu_test.py build/nxtsOS.iso 128 logs/serial.log /tmp/nxts-mon.sock
