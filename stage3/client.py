import socket
import hashlib
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode
from random import randint

def hash_md5(message):
	hash_md5 = hashlib.md5()
	hash_md5.update(message)
	return hash_md5.digest()

def make_message(header, message):
	while len(header) < 1024:
		header = header + chr(00)
	return header + message + hash_md5(message)

def check_hash(message):
	# use case: return true if not corrupted  input: received message
	val = message[1024:len(message)-16]
	hash_value = message[-16:]
	if( hash_md5(val) == hash_value ):
		return True
	else:
		return False
def get_message(message):
	return message[1024:len(message)-16]

def get_first(message):
	end_loc = message.find("|")
	return message[1:end_loc - 1]

def get_next(message):
	start_loc = message.find("|")
	end_loc = message.find("|", start_loc + 1)
	return message[start_loc + 1:end_loc - 1]

public_key = open('client_public_key', 'r').read()
rsakey = RSA.importKey(public_key)
rsakey = PKCS1_OAEP.new(rsakey)
private_key = open('client_private_key', 'r').read()
rsakey_pri = RSA.importKey(private_key)
rsakey_pri = PKCS1_OAEP.new(rsakey_pri)
KDC_public_key = open('KDC_private_key', 'r').read()
rsakey_KDC = RSA.importKey(KDC_public_key)
rsakey_KDC = PKCS1_OAEP.new(rsakey_KDC)



s = socket.socket()
host = socket.gethostname()
port = 30000
cert = "cert1"

s.connect((host, port))
msg = s.recv(4096)
msg = rsakey_pri.decrypt(msg)
s_num = int(msg)

request = "10.122.108.202"
k = socket.socket()
k_host = socket.gethostname()
k_port = 40000
k.connect((k_host, k_port))
k.send(request)
pack = k.recv(4096)
num = randint(0,1023)

if pack == "You are not in list":
	print pack
elif pack == "Des is not in the list":
	print pack
	
# Get Server Public Key
pack = RSA.importKey(pack)
pack = PKCS1_OAEP.new(pack)
pk = pack

msg = str(s_num) + "|" + str(num)
msg = pk.encrypt(msg)
s.send(msg)
response = s.recv(4096)
if int(response) == num:
	print "He is Server"
else:
	print "You are not talking to server"

msg = s.recv(4096);
if msg == "new patch":
	print "New patch notified"
	# nothing for header
	cert = rsakey.encrypt(cert)
	s.send(make_message("",cert))
	msg = s.recv(4096)
	if msg == "Certificate success":
		patch = s.recv(4096)
		if check_hash(patch) == False:
			print "hash check failed!!"
		else:
			print "hash check passed!!"
			patch = rsakey_pri.decrypt(get_message(patch))
			print patch
	else:
		print "Certificate is wrong, plz check"
else:
	print "No patch, keep doing"
	

s.close()