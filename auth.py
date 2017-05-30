
from scapy.all import *

import socket
import os
import pytap
import md5

STATES = ["Closed", "Authenticated"]
current_states = {"10.10.0.2": 0, "10.10.0.3": 0}
SERVER_UDP_PORT = 5050
SERVER_UDP_IP = "128.199.177.106"

users = {"10.10.0.2": md5.new("pw1").digest(), "10.10.0.3": md5.new("pw2").digest()}
addresses = {"10.10.0.2": None, "10.10.0.3": None}

def validate_user(username, pw):
    if users[username] == pw:
        return True
    else:
        return False

def send_auth_packet(sock, username, pw):
    sock.sendto("username:"+username+":"+md5.new(pw).digest(), (SERVER_UDP_IP, 5050))
    return

def recv_auth(sock, addr, message):
    username = message.split(':')[1]
    pw = message.split(':')[2]
    if validate_user(username, pw):
        sock.sendto("Authenticated", addr)
        addresses[username] = addr
        current_states[username] = 1
        return True
    else:
        return False
    return

def recv_disconnect(sock, addr, username, pw):
    if validate_user(user, pw):
        sock.sendto("Disconnected", addr)
        addresses[username] = None
        current_states[username] = 0


