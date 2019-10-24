import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import base64
from Crypto.Cipher import PKCS1_OAEP

from Crypto.Signature import pkcs1_15
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from base64 import b64encode, b64decode
import rsa


hash = "SHA-256"

def newkeys(keysize):
    random_generator = Random.new().read
    key = RSA.generate(keysize, random_generator)
    private, public = key, key.publickey()
    return public, private


def importKey(externKey):
    return RSA.importKey(externKey)

def getpublickey(priv_key):
    return priv_key.publickey()

def encrypt(message, pub_key):
    #RSA encryption protocol according to PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message)


def decrypt(ciphertext, priv_key):
    #RSA encryption protocol according to PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(ciphertext)

def sign(message, priv_key, hashAlg="SHA-256"):
    global hash
    hash = hashAlg
    signer = PKCS1_v1_5.new(priv_key)
    if (hash == "SHA-512"):
        digest = SHA512.new()
    elif (hash == "SHA-384"):
        digest = SHA384.new()
    elif (hash == "SHA-256"):
        digest = SHA256.new()
    elif (hash == "SHA-1"):
        digest = SHA.new()
    else:
        digest = MD5.new()
    digest.update(message)
    return signer.sign(digest)

def verify(message, signature, pub_key):
    signer = PKCS1_v1_5.new(pub_key)
    if (hash == "SHA-512"):
        digest = SHA512.new()
    elif (hash == "SHA-384"):
        digest = SHA384.new()
    elif (hash == "SHA-256"):
        digest = SHA256.new()
    elif (hash == "SHA-1"):
        digest = SHA.new()
    else:
        digest = MD5.new()
    digest.update(message)
    return signer.verify(digest, signature)
    
(public, private) = rsa.newkeys(2048)


def sender(text,port):
    
    keysize = 2048
    msg = text + str(port)
    msg = bytes(msg, 'utf-8')
    packet = b64encode(rsa.encrypt(msg, public))
    sender_sign = b64encode(rsa.sign(msg, private, "SHA-512"))    
    return packet,sender_sign,port
    
    
def firewall(text,port):
    accepted_ports = [21,777,80,20]
    #port=20
    
    (p,ss,port) = sender(text,port)
    if port in accepted_ports:
        d,v=rec(p,ss)
        return d,v
    else:
        #print("Intrusion from different port "+str(port))
        d= False
        v= False
        return d,v
        
    
def rec(packet,sender_sign):
    decrypted = rsa.decrypt(b64decode(packet), private)
    #print(decrypted)

    verify = rsa.verify(decrypted, b64decode(sender_sign), public)
    #print("the digital signature matches that of sender, the hash: "+str(verify))
    return decrypted,verify

#firewall()


import tkinter as tk

def function():
    print("TEXT: %s\nPORT: %s" % (e1.get(), e2.get()))

    d,v = firewall(e1.get(),int(e2.get().strip()))
    if d!=False:
        e3.insert('1.0',"Decrpyted text : "+ str(d)+"\n"+"the digital signature matches that of sender, the hash: "+str(v))
    else:
        e3.insert('1.0',"Alert! Intrusion from different port "+str(e2.get().strip()))

    
def clear():
    e1.delete(0, tk.END)
    e2.delete(0, tk.END)
    e3.delete('1.0', tk.END)

master = tk.Tk()
master.title('Traffic Analysis')

tk.Label(master, text="ENTER MESSAGE TO BE SENT").grid(row=0)

tk.Label(master, text="PORT NUMBER").grid(row=1)

tk.Label(master, text="OUTPUT").grid(row=4)



e1 = tk.Entry(master)
e2 = tk.Entry(master)

e3 = tk.Text(master)

e1.grid(row=0, column=1)
e2.grid(row=1, column=1)

e3.grid(row = 5,column = 1)


tk.Button(master, 
          text='CONFIRM DETAILS', command=function).grid(row=6, 
                                                       column=2, 
                                                       sticky=tk.W, 
                                                       pady=4)
tk.Button(master, 
          text='CLEAR', command=clear).grid(row=6, 
                                                       column=4, 
                                                       sticky=tk.W, 
                                                       pady=4)

tk.Button(master, 
          text='Quit', 
          command=master.destroy).grid(row=6, 
                                    column=0, 
                                    sticky=tk.W, 
                                    pady=4)

master.mainloop()

