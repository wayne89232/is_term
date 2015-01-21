from Crypto.PublicKey import RSA 

new_key = RSA.generate(1024) 
public_key = new_key.publickey().exportKey("PEM") 
private_key = new_key.exportKey("PEM")

public = open("public_key", "w")
public.write(str(public_key))

private = open("private_key", "w")
private.write(str(private_key))
