import socket
import hashlib
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA 
from Crypto.Cipher import PKCS1_OAEP
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


public_key = open('server_public_key', 'r').read()
private_key = open('client_private_key', 'r').read()
rsakey = RSA.importKey(public_key)
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
			patch = rsakey_pri.decrypt(get_message(patch))
			print patch
	else:
		print "Certificate is wrong, plz check"
else:
	print "No patch, keep doing"
	

s.close()