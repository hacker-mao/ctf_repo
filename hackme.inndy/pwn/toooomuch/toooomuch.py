from pwn import *
from ctypes import *

#p = process('./toooomuch')
p = remote('hackme.inndy.tw',7702)
dll = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
p.recvuntil('passcode: ')
p.sendline('43210')
dll.srand(dll.time(0))
p.recvuntil('0 to 100: ')
num = dll.rand() % 100
p.sendline(str(num))

p.interactive()