#coding : utf-8
from Crypto.Cipher import AES
from Crypto import Random


key = '1b2e3546586e72869ba7b5c8d9efff0c'.decode('hex')
cipher = AES.new(key, AES.MODE_ECB)
msg = cipher.decrypt('461559ceb56d277df44a31ae89f08a6a33626430326635343563373032383031'.decode('hex'))


print msg.encode('hex')[:32].decode('hex')
print "461559ceb56d277df44a31ae89f08a6a33626430326635343563373032383031"[32:].decode('hex')


