from pwn import *

flag_bytes = [
    0xB5B6B6F8C0D0C0C5, 0xB3E6BAE0B6E6B3B5, 0xB2BABBBBBAE7BBB7, 0xE1E6B1B1BAB1E6B4,
    0xE6B0B5B3B3B0B2B2, 0xE1E7B3B0B3B2E0E1, 0xE7E5B2BBE2B6B1B3, 0xE1B6B4E2E7E1B7B3 
]

raw_bytes = b''
for bytestr in flag_bytes:
    raw_bytes += p64(bytestr)

raw_bytes += p32(0xE0B2E1E2)
raw_bytes += p16(0xfeb0)

flag = xor(raw_bytes, 0x83)

print(flag.decode('utf-8'))
