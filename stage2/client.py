import socket
import hashlib
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5 
from base64 import b64decode

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

def sign_data(key, data):
	from Crypto.Hash import MD5
	h = MD5.new()
	h.update(data)
	sign = key.sign(h) 
	# sign = key.sign(hash_md5(data)) 
	return sign

def verify_sign(key, sign, data):
	from Crypto.Hash import MD5
	h = MD5.new()
	h.update(data)	
	if key.verify(h, sign):
		return True
	return False

def get_header(data):
	return data.split(chr(00))[0]

public_key = open('server_public_key', 'r').read()
private_key = open('client_private_key', 'r').read()
rsakey = RSA.importKey(public_key)
sign_key = PKCS1_v1_5.new(rsakey) 
rsakey = PKCS1_OAEP.new(rsakey)
# print(rsakey) 
rsakey_pri = RSA.importKey(private_key)
rsakey_pri = PKCS1_OAEP.new(rsakey_pri)
# print(rsakey_pri)


s = socket.socket()
host = socket.gethostname()
port = 30000
cert = "cert1"



s.connect((host, port))


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
			if verify_sign(sign_key,get_header(patch), get_message(patch)):
				print "Signature verification passed"
				patch = rsakey_pri.decrypt(get_message(patch))
				print patch
			else:
				print "Signature verification failed"
	else:
		print "Certificate is wrong, plz check"
else:
	print "No patch, keep doing"
	

s.close()