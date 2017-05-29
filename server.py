#!/usr/bin/env python

#
#  Fake ICMP and ARP responses from non-existings IPs via tap0.
#  Create fake MAC addresses on the fly.
#  Present a 'rot13' TCP echo service on any IP and port.  
#

from scapy.all import *
from pytun import TunTapDevice
import pytun
import os
import time

BASE_IP = "10.10.0.2"
SERVER_IP = "10.10.0.1"

# Open tun0 device
tun = TunTapDevice("leamit0",pytun.IFF_TUN| pytun.IFF_NO_PI)
tun.addr = SERVER_IP
tun.dstaddr = "10.10.0.2"
tun.netmask = "255.255.255.0"
tun.mtu = 1500
#tun.persist(True)
tun.up()

# About-face for a packet: swap src and dst in specified layer
def swap_src_and_dst(pkt, layer):
  pkt[layer].dst, pkt[layer].src = pkt[layer].src, pkt[layer].dst 

#
#  Now process packets
#
while 1:
  binary_packet = tun.read(tun.mtu)   # get packet routed to our "network"
  
  raw_packet = IP(binary_packet)        # Scapy parses byte string into its packet object
  
  print raw_packet.show()

  time.sleep(2)
