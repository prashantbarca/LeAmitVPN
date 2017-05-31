
from scapy.all import *
from amitcrypto import *

import time
import socket
import os
import pytap
import md5


STATES = ["Closed", "Authenticated"]              # Label of states for client
current_states = {"10.10.0.2": 0, "10.10.0.3": 0} # State machine for client
SERVER_UDP_PORT = 5050            # Random port
SERVER_UDP_IP = "128.199.177.106" # prashant.at

users = {"10.10.0.2": md5.new("pw1").digest(), "10.10.0.3": md5.new("pw2").digest()} # Keeps track of usernames and passwords. I know MD5 is bad!
addresses = {"10.10.0.2": None, "10.10.0.3": None} # Keeps track of current communicating person
messages = {"10.10.0.2": [], "10.10.0.3": []}

# get client message queue object
def get_message_queue(addr):
    for k,v in messages.iteritems():
        if k == addr:
            return k
    return None

# received a message for the client
def message_for_client(addr,message):
    idx = get_message_queue(addr)
    if idx != None:
        messages[idx].append(message)

def get_messages_for_client(addr):
    idx = get_message_queue(addr)
    if idx != None:
        return messages[idx]
    else:
        return None

# Server authenticates user
def validate_user(username, pw):
    if users[username] == pw:
        return True
    else:
        return False

# Client sends authentication message
def send_auth_packet(sock, username, pw):
    message = "username:"+username+":"+md5.new(pw).digest()+":" + str(time.time())
    aesobj = AESCipher.new(key)
    
    sock.sendto(aesobj.encrypt(message), (SERVER_UDP_IP, 5050))
    return

# Server receives message and decides if its an auth message
def recv_auth(sock, addr, encmessage):
    aesobj = AESCipher.new(key)
    message = aesobj.decrypt(encmessage)
    print "Recv auth method entered"
    try:
        username = message.split(':')[1]
        pw = message.split(':')[2]
        print username
        print pw, len(pw)
        print users[username], len(users[username])
        print users[username] == pw
        if validate_user(username, pw):
            print "Authenticated"
            sock.sendto("Authenticated", addr)
            addresses[username] = addr
            current_states[username] = 1
            messages[username].append(message)
            return True
        else:
            return False
    except:
        return False

# Check if addr exists in dictionary
def check_if_addr_exists(addr):
    for k,v in addresses.iteritems():
        if v == addr:
            return k
    return None
