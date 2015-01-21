import socket
import hashlib
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP

def pack_key(key, message):
	return key + "|" + message

private_key = open('KDC_public_key', 'r').read()
rsakey_pri = RSA.importKey(private_key)
rsakey_pri = PKCS1_OAEP.new(rsakey_pri)
pk1 = open('client_public_key', 'r').read()
pk1 = RSA.importKey(pk1)
pk1 = PKCS1_OAEP.new(pk1)
pk2 = open('server_public_key', 'r').read()
pk2 = RSA.importKey(pk2)
pk2 = PKCS1_OAEP.new(pk2)


s = socket.socket()
host = socket.gethostname()
port = 40000
s.bind((host, port))
print "host on", host

# Create IP list with each public key  (IP, port, public key)
IP_list = ['192.168.1.62', 11111, pk1], ["127.0.0.1", 22222, "KEY"]


s.listen(5)

while True:
	c, addr = s.accept()
	print 'Got connection from', addr
	request = c.recv(4096)
	#If in the list
	check = 1
	for x in xrange(0,1):
		if addr[0] == IP_list[x][0]:
			check = 0;
			break
	if check == 1:
		print "Not in list"
		reply = "You are not in list"
		reply = rsakey_pri.encrypt(reply)
		c.send(reply)
		break
	
	#Find B public key
	check = 1
	b_index = -1
	for x in xrange(0,1):
		if request == IP_list[x][0]:
			check = 0
			b_index = x
			break;
	if check == 1:
		print "Des is not in the list"
		reply = "Des is not in the list"
		reply = rsakey_pri.encrypt(reply)
		c.send(reply)
		break
	
	#pack B public key|AIP|BIP|T1
	# reply = IP_list[b_index][2]
	reply = "not work yet"
	reply = rsakey_pri.encrypt(reply)
	c.send(reply)
	
c.close()