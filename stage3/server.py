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
	return message[0:end_loc]

def get_next(message):
	start_loc = message.find("|")
	return message[start_loc+1:len(message)]


public_key = open('client_public_key', 'r').read()
rsakey = RSA.importKey(public_key)
rsakey = PKCS1_OAEP.new(rsakey)
private_key = open('client_private_key', 'r').read()
rsakey_pri = RSA.importKey(private_key)
rsakey_pri = PKCS1_OAEP.new(rsakey_pri)
KDC_public_key = open('KDC_private_key', 'r').read()
rsakey_KDC = RSA.importKey(KDC_public_key)
rsakey_KDC = PKCS1_OAEP.new(rsakey_KDC)

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
		# connect to KDC
		request = addr[0]
		k = socket.socket()
		k = socket.socket()
		k_host = socket.gethostname()
		k_port = 40000
		k.connect((k_host, k_port))
		k.send(request)
		pack = k.recv(4096)
		# pack = rsakey_KDC.decrypt(pack)
		num = randint(0,1023)

		if pack == "You are not in list":
			print pack
			break
		elif pack == "Des is not in the list":
			print pack
			break
		# Get Client Public key
		pack = RSA.importKey(pack)
		pack = PKCS1_OAEP.new(pack)
		
		pk = pack
		# Challenge Client
		msg = pk.encrypt(str(num))
		c.send(msg)
		# Recieve Client Challenge
		challenge = c.recv(4096)
		challenge = rsakey_pri.decrypt(challenge)
		response = get_first(challenge)
		challenge = get_next(challenge)
		if int(response) == num:
			print "He is the client!"
			c.send(challenge)
		else:
			print "You are not talking to client!"
			break

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
				c.send(make_message("",a))
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