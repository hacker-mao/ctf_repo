# 0F 10 14 20 10 16 00 09  24 02 15 16 E9 12 16 E8
# 02 17 16 13 16 90 06 15  17 45 06 15 16 76 01 15
# 16 12 16 FF 0A 14 16 0C  09 0E ?? ?? ?? ?? ?? ??

# 0f scanf
# 09 jmp
# 0c cmp

# scanf('%s',s)

# *(&v7 + *(v5 + 1 + a1) -20) = *(v5 + 2 + a1)
# v7[0] = 0x20
# i = 0x00
# v5 = 0x24

# if 0x20 != i:
# 	v5 = 0x9
# else:
# 	v5 += 2

# a = s[i]

# b = s[i+1]

# a ^= b
# a ^= i

# s[i] = a

# ++i


# if 0x20 != i:
# 	v5 = 0x9
# else:
# 	v5 += 2

# for i in range(len(s)):
# 	a = s[i]
# 	b = s[i+1]
# 	a ^= b
# 	a ^= i
# 	s[i] = a

flag = 'f'

s2 = [0x0a, 0x0c, 0x04, 0x1f, 0x48, 0x5a, 0x5f, 0x03, 0x62, 0x67, 0x0e, 0x61, 0x1e, 0x19, 0x08, 0x36, 0x47, 0x52, 0x13, 0x57, 0x7c, 0x39, 0x54, 0x4b, 0x05, 0x05, 0x45, 0x77, 0x15, 0x26, 0x0e, 0x62]

while True:

	if len(flag) >= 0x20:
			break

	for i in range(0x20,0x7f):
		j = len(flag)
		a = ord(flag[j-1])
		b = i
		a ^= b
		a ^= (j-1)
		if a == s2[j-1]:
			flag += chr(i)
			break

		

print flag






