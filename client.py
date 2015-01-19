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
encrypted = rsakey.encrypt(message)


s = socket.socket()
host = socket.gethostname()
port = 30000
certs = ["cert1", "cert2"]

s.connect((host, port))
msg = open('msg', 'r')
a = msg.read()
if len(str(a)) != 0:
	notify = "new patch"
	s.send(notify.encode())
	print "Notified."
	if s.recv(1024).decode() in certs:
		print "Certificate success! Send patch file."
		s.send(str(a).encode())
	else:
		print "certificate failed"
else:
	print "no patch!"

s.close