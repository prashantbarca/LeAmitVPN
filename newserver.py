#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2017 prashant <prashant@prashant>
#
# Distributed under terms of the MIT license.

"""

"""
import socket
from scapy.all import *
def swap_src_and_dst(pkt, layer):
    pkt[layer].dst, pkt[layer].src = pkt[layer].src, pkt[layer].dst 

UDP_PORT=5050
UDP_IP = "128.199.177.106"
sock = socket.socket(socket.AF_INET, # Internet
        socket.SOCK_DGRAM) 
sock.bind((UDP_IP, UDP_PORT))
while True:
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    print "received message:", data.encode("hex")
    packet = IP(data)
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        pong = packet.copy() 
        swap_src_and_dst(pong, IP)
        #swap_src_and_dst(pong, ICMP)
        pong[ICMP].type='echo-reply'
        pong[ICMP].chksum = None
        pong[IP].chksum = None
        print pong.show() 
        print pong.summary()
        sock.sendto(pong.build(), addr)
