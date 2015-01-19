import socket
import hashlib
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode


public_key = open('public_key', 'r').read()
private_key = open('private_key', 'r').read()
rsakey = RSA.importKey(public_key)
rsakey = PKCS1_OAEP.new(rsakey)
print(rsakey) 
rsakey_pri = RSA.importKey(private_key)
rsakey_pri = PKCS1_OAEP.new(rsakey_pri)
print(rsakey_pri)



s = socket.socket()
host = socket.gethostname()
port = 30000
cert = "cert1"
cert = rsakey.encrypt(cert)


s.connect((host, port))


msg = s.recv(1024);
if msg == "new patch":
	print "new patch?"
	s.send(cert)
	msg = s.recv(1024)
	if msg == "Certificate success":
		patch = s.recv(1024)
		patch = rsakey_pri.decrypt(patch)
		print patch
	else:
		print "Certificate is wrong, plz check"
else:
	print "No patch, keep doing"
	

s.close