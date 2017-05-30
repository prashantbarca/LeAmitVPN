
from Crypto.Cipher import AES

aesobj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')

def encrypt(sock, message, addr):
    sock.sendto(aesobj.encrypt(message), addr)

def decrypt(sock, message, addr):
    return aesobj.decrypt(message)
