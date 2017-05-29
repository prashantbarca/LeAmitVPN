#!/usr/bin/env python

from pytun import TunTapDevice
from scapy.all import *
import os
import pytun
import time

SERVER_IP = "10.10.0.1"

# Open tun0 device
tun = os.open("/dev/net/tun", os.O_WRONLY)

while 1:
    packet = IP(src="10.10.0.2",dst="10.10.0.8")/ICMP()
    packet.show()
    os.write(tun,packet.build())
    time.sleep(4)
