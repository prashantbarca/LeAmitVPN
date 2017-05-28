#!/usr/bin/env python

from pytun import TunTapDevice
from scapy import *

SERVER_IP = "10.10.0.1"

# Open tun0 device
tun = TunTapDevice()
tun.addr = "10.10.0.2"
tun.dstaddr = SERVER_IP
tun.netmask = "255.255.255.0"
tun.mtu = 1500
tun.up()

while 1:
    packet = IP(dst="10.10.0.3")/TCP(dport=1000)/"hello world"
    tun.write(hexdump(packet))
