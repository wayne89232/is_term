import socket
import hashlib
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP

public_key = open('public_key', 'r').read()
print(public_key)
rsakey = RSA.importKey(public_key)
rsakey = PKCS1_OAEP.new(rsakey)
print(rsakey) 
# encrypted = rsakey.encrypt(message)

# open patch
msg = open('msg', 'r')
a = msg.read()

s = socket.socket()
host = socket.gethostname()
port = 30000
s.bind((host, port))
certs = ["cert1", "cert2"]
print "host on", host

s.listen(5)
c, addr = s.accept()
print 'Got connection from', addr

while True:
	if len(str(a)) != 0:
		notify = "new patch"
		c.send(notify.encode()) #Need encrypt??
		print "Notified."
		client_cert = c.recv(1024)
		cert = rsakey.decrypt(client_cert)
		if cert in certs:
			print "Certificate success! Send patch file."
			c.send("Certificate success")
			c.send(str(a).encode())
		else:
			c.send("Certificate failed")
			print "certificate failed"
			break
	else:
		notify = "no patch"
		c.send(notify.encode()) #Need encrypt??
		print "no patch!"
c.close()