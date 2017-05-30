
from scapy.all import *

import socket
import os
import pytap
import md5

SERVER_UDP_PORT = 5050
SERVER_UDP_IP = "128.199.177.106"

users = {"10.10.0.2": md5.new("pw1").digest(), "10.10.0.3": md5.new("pw2").digest()}
addresses = {"10.10.0.2": None, "10.10.0.3": None}

def validate_user(username, pw):
    if users[username] == md5.new(pw).digest():
        return True
    else:
        return False

def send_auth_packet(sock, username, pw):
    sock.sendto("username:"+username+":"+md5.new(pw).digest(), (SERVER_UDP_IP, 5050))
    return

def recv_auth(sock, message):    
    username = message
    pw = message
    if validate_user(username, pw):
        return True
    else:
        return False
    return


