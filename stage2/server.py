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


public_key = open('client_public_key', 'r').read()
private_key = open('server_private_key', 'r').read()
rsakey = RSA.importKey(public_key) 
rsakey = PKCS1_OAEP.new(rsakey)
# print(rsakey) 
rsakey_pri = RSA.importKey(private_key)
sign_key = PKCS1_v1_5.new(rsakey_pri)
rsakey_pri = PKCS1_OAEP.new(rsakey_pri)
# print(rsakey_pri)

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
		c.send(notify)
		print "Notified."
		client_cert = c.recv(4096)
		if check_hash(client_cert) == False:
			print "hash check failed!!"
		else:
		# Decode certification
			print "hash check passed!!"
			cert = rsakey_pri.decrypt(get_message(client_cert))
			if cert in certs:
				print "Certificate success! Send patch file."
				c.send("Certificate success")
				a = rsakey.encrypt(a)
				c.send(make_message(sign_data(sign_key, a),a))
				break
			else:
				c.send("Certificate failed")
				print "certificate failed"
				break
	else:
		notify = "No patch"
		c.send(notify)
		print "no patch!"
		break
c.close()