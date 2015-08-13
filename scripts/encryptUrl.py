from Crypto.Cipher import AES
import hashlib
import base64
import sys

if len(sys.argv) < 5:
	print 'Usage:\n\tphp encryptUrl.php <base url> <encrypted part> <encryption key> <encryption iv>'
	sys.exit(1)

BASE_URL = sys.argv[1]
ENC_URL = sys.argv[2]
ENC_KEY = sys.argv[3].decode('hex')
ENC_IV = sys.argv[4].decode('hex')
HASH_SIZE = 8

def pkcs7encode(text, blockSize = 16):
	val = blockSize - (len(text) % blockSize)
	for _ in xrange(val):
		text += chr(val)
	return text

m = hashlib.md5()
m.update(ENC_URL)
signedUrl = m.digest()[:HASH_SIZE] + ENC_URL
	
aes = AES.new(ENC_KEY, AES.MODE_CBC, ENC_IV)
encryptedUrl = base64.urlsafe_b64encode(aes.encrypt(pkcs7encode(signedUrl))).rstrip('=')

print BASE_URL + encryptedUrl
