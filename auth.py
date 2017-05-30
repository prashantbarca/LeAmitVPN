
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
auth_messages = {"10.10.0.2": [], "10.10.0.3": []} # Important to prevent replay attacks
seq_messages = {"10.10.0.2": [], "10.10.0.3": []}  # This will keep a list of tuples - seq, ack_seq pairs. 

# We think it will be easy to route packets... But... Its to be seen

# Check who the message must be routed to
def route_message(message):
    return

# Server authenticates user
def validate_user(username, pw):
    if users[username] == pw:
        return True
    else:
        return False

# Client sends authentication message
def send_auth_packet(sock, username, pw):
    sock.sendto("username:"+username+":"+md5.new(pw).digest()+":"+ str(time.time()), (SERVER_UDP_IP, 5050))
    return

# Server receives message and decides if its an auth message
def recv_auth(sock, addr, message):
    try:
        username = message.split(':')[1]
        pw = message.split(':')[2]
        if validate_user(username, pw) and message not in auth_messages[username]:
            sock.sendto("Authenticated", addr)
            addresses[username] = addr
            current_states[username] = 1
            messages[username].append(message)
            return True
        else:
            return False
    except:
        return False

# Server receives a disconnect
def recv_disconnect(sock, addr, username, pw):
    if validate_user(user, pw):
        sock.sendto("Disconnected", addr)
        addresses[username] = None
        current_states[username] = 0


# Check if addr exists in dictionary
def check_if_addr_exists(addr):
    for k,v in addresses.iteritems():
        if v == addr:
            return k
        else:
            return None


