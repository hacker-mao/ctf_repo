#coding: utf-8


def sbox_init(sbox_seed):
    sbox = []
    for i in range(256):
        sbox.append(i)


    for i in range(8):

        v1 = ord(sbox_seed[i])
        v2 = i

        for j in range(36):
            v2 = (13 * (~v2)) & 0xff
            v1 = (17 * (~v1)) & 0xff
            v4 = sbox[v2]
            sbox[v2] = sbox[v1]
            sbox[v1] = v4

    return sbox


def rc87_enc(date,passwd,sbox):

    for i in range(len(date)):

        date_byte = ord(date[i])
        v6 = ord(passwd[i % len(passwd)]) #passwd_byte
        v7 = i % len(passwd)

        for j in range(36):

            v7 = (13 * (~v7)) & 0xff
            v6 = (17 * (~v6)) & 0xff
            v8 = sbox[v7]
            sbox[v7] = sbox[v6]
            sbox[v6] = v8

        v9 = 0xdeadbeef

        for l in range(256):
            v11 = sbox[l] & 0xff
            v9 = (0xc8763 * v11 ^ 0x5a77 * v9) & 0xffffffff

        output_byte = ( ((17 * date_byte)) ^ v9 ) & 0xff
        print 'output_byte: %x'%output_byte
        #return output_byte


def get_IV_cipher(encrypted_file):
    f = open(encrypted_file,'rb')
    tmp = f.read()
    IV = tmp[:8]
    cipher = tmp[8:]
    f.close()
    return IV,cipher

def get_plain(input_file):
    f = open(input_file,'rb')
    plain = f.read()
    f.close()
    return plain

if __name__ == '__main__':
   IV,cipher = get_IV_cipher('./321')
   #print IV.encode('hex'),cipher.encode('hex')
   plain = get_plain('./123')
   #print plain.encode('hex')
   sbox = sbox_init(IV)
   rc87_enc(plain,'1234',sbox)

