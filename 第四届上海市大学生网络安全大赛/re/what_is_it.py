import hashlib
import itertools

def md5_crypto(data):

    md = hashlib.md5()
    md.update(data)
    sigh = md.hexdigest()
    return sigh

charset = [chr(i) for i in range(97,123)]
inputs = itertools.product(charset,repeat=6)

for i in inputs:
    input = "".join(i)
    cipher = md5_crypto(input)

    v15 = 0
    v14 = 0
    for i in range(32):
        if cipher[i] == '0':
            v15 += 1
            v14 += i

    if (10 * v15 + v14 == 403):
        print input
        exit()