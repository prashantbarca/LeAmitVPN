from Crypto.Cipher import XOR

key = "abcdefghijklij"
xor = XOR.XORCipher(key) # To encrypt
xor1 = XOR.XORCipher(key) # To decrypt

def enc(sock, message, addr):
    abcd = xor.encrypt(message)
    sock.sendto(abcd, addr)
    return abcd

def dec(sock, message, addr):
    abcd = xor1.decrypt(message)
    return abcd

#message = "dfjsdfjsdfjdsfdfsk"
#print message
#newm = enc(1, message, message)
#print newm
#print dec(1, newm, newm)
