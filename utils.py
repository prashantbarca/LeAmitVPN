
from scapy.all import *
import amitcrypto

import time
import socket
import os
import md5

key = "abcdefghijklij"

SERVER_UDP_PORT = 5050            # Random port
SERVER_UDP_IP = "128.199.177.106" # prashant.at

users = {"10.10.0.2": md5.new("pw1").digest(), "10.10.0.3": md5.new("pw2").digest()} # Keeps track of usernames and passwords. I know MD5 is bad!
addresses = {"10.10.0.2": None, "10.10.0.3": None} # Keeps track of current communicating person
messages = {"10.10.0.2": [], "10.10.0.3": []}

# get a message for another client
def receive_non_auth_message(data):
    packet = IP(data)
    print packet.summary()

# get client message queue object
def get_message_queue(addr):
    for k,v in messages.iteritems():
        if k == addr:
            return k
    return None

# received a message for the client
def message_for_client(addr,message):
    address = get_message_queue(addr)
    
    if address != None:
        print 'appending '+str(message)+' for '+address
        messages[address].append(message)

def get_messages_for_client(addr):
    address = get_message_queue(addr)
    if address != None:
        return messages[address]
    else:
        return None

def clear_messages(public_ip):
    print 'public ip is '+str(public_ip)
    lan_addr = check_if_addr_exists(public_ip)
    print 'clearing messages for '+str(lan_addr)
    if lan_addr != None:
        messages[lan_addr] = []
    
# Server authenticates user
def validate_user(username, pw):
    if users[username] == pw:
        return True
    else:
        return False

# Client sends authentication message
def send_auth_packet(sock, username, pw):
    print "Client -> Server : Sending poll packet"
    message = "username:"+username+":"+pw+":" + str(time.time())
    aesobj = amitcrypto.AESCipher(key)
    
    #sock.sendto(aesobj.encrypt(message), (SERVER_UDP_IP, 5050))
    sock.sendto(message, (SERVER_UDP_IP, 5050))
    return

# Server receives message and decides if its an auth message
def recv_auth(sock, addr, encmessage):
    aesobj = amitcrypto.AESCipher(key)
    #message = aesobj.decrypt(encmessage)
    message = encmessage
    #print "Recv auth method entered"
    try:
        username = message.split(':')[1]
        pw = message.split(':')[2]
        #print username
        #print pw, len(pw)
        #print users[username], len(users[username])
        #print users[username] == pw
        if validate_user(username, pw):
            print "Valid poll received from " + username
            addresses[username] = addr
            return True
        else:
            return False
    except:
        return False

# get public ip for user
def get_public_ip(addr):
    for k,v in addresses.iteritems():
        if k == addr:
            return v
    return None

# Check if addr exists in dictionary
def check_if_addr_exists(addr):
    for k,v in addresses.iteritems():
        print 'value type : ' + type(v) + 'value addr: '+ type(addr)
        print 'address key '+str(k)+' public ip '+str(v) + 'addr ' + str(addr)
        if v == addr:
            return k
    return None
