import socket
import hashlib
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP


public_key = open('public_key', 'r').read()
private_key = open('private_key', 'r').read()
print(str(public_key))
rsakey = RSA.importKey(public_key)
rsakey = PKCS1_OAEP.new(rsakey)


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
		patch = s.recv(1024).decode()
		print patch
	else:
		print "Certificate is wrong, plz check"
else:
	print "No patch, keep doing"
	# recv = open("recv", "w")
	# recv.write(msg)
	# print "patch success"
	# break

s.close