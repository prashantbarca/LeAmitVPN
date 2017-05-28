#!/usr/bin/env python

from pytun import TunTapDevice
from scapy.all import *
import os

SERVER_IP = "129.170.212.225"

# Open tun0 device
tun = TunTapDevice()
tun.addr = "10.10.0.2"
tun.dstaddr = SERVER_IP
tun.netmask = "255.255.255.0"
tun.mtu = 1500
tun.up()

while 1:
    packet = IP(src="10.10.0.2",dst="8.8.8.8")/ICMP()
    packet.show()
    tun.write(packet.build())
