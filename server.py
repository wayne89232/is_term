import socket
import hashlib
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP

public_key = open('public_key', 'r').read()
print(public_key)
rsakey = RSA.importKey(public_key)
rsakey = PKCS1_OAEP.new(rsakey)
print() 
encrypted = rsakey.encrypt(message)



s = socket.socket()
host = socket.gethostname()
port = 30000
s.bind((host, port))
cert = "cert1"
# cert = rsakey.encrypt(cert)
print "host on", host

s.listen(5)
c, addr = s.accept()
print 'Got connection from', addr
while True:
	msg = c.recv(1024).decode()
	if msg == "new patch":
		print "new patch?"
		c.send(cert.encode())
	else:
		recv = open("recv", "w")
		recv.write(msg)
		print "patch success"
		break
c.close()