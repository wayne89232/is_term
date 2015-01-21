import socket
import hashlib
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP

def get_desIP(message):
	start_loc = message.find("|");
	end_loc = message.find("|", start_loc + 1)
	return message[start_loc + 1:end_loc - 1]

def pack_key(key, message):
	return key + "|" + message


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

# Create IP list with each public key  (IP, port, public key)
IP_list = ["127.0.0.1", 11111, "A public key"], ["127.0.0.1", 22222, "B public key"]


s.listen(5)
c, addr = s.accept()
print 'Got connection from', addr

while True:
	#If in the list
	check = 1
	for x in xrange(1,2):
		if addr == IP_list[x, 1]:
			check = 0;
			break
	if check == 1:
		print "You are not in list"
		break

	# recv the request
	#request has AIP|BIP|T1
	request = c.recv(1024)

	#Find B public key
	b_IP = get_desIP(request)
	check = 1
	b_index = -1
	for x in xrange(1,2):
		if b_IP == IP_list[x, 1]:
			check = 0
			b_index = x
			break;
	if check == 1:
		print "Des is not in the list"
		break
	
	#pack B public key|AIP|BIP|T1
	reply = pack_key(IP_list[b_index, 3], request)
	reply = rsakey_pri.encrypt(reply)
	s.send(reply)
	
c.close()