import socket
import hashlib
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP


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
port = 40000
s.bind((host, port))
print "host on", host

# Create IP list with each public key

s.listen(5)
c, addr = s.accept()
print 'Got connection from', addr

while True:
	#If in the list
	request = c.recv(1024)
	#request has AIP|BIP|T1
	#Find B public key
	#pack B public key|AIP|BIP|T1
	reply = rsakey_pri.encrypt(reply)
	s.send(reply)
	
c.close()