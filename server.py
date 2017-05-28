#!/usr/bin/env python

#
#  Fake ICMP and ARP responses from non-existings IPs via tap0.
#  Create fake MAC addresses on the fly.
#  Present a 'rot13' TCP echo service on any IP and port.  
#

from scapy.all import *
from pytun import TunTapDevice

import os
import codecs   # gimme rot13

BASE_IP = "10.10.0.2"
SERVER_IP = "10.10.0.1"

# Open tun0 device
tun = TunTapDevice()
tun.addr = SERVER_IP
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
  '''
  if packet.haslayer(ICMP) and packet[ICMP].type == 8 : # ICMP echo-request
    pong = packet.copy()
    swap_src_and_dst(pong, Ether)
    swap_src_and_dst(pong, IP)
    pong[ICMP].type='echo-reply'
    pong[ICMP].chksum = None   # force recalculation
    pong[IP].chksum   = None
    tun.write(pong.build())  # send back to the kernel

  elif packet.haslayer(TCP) and packet[TCP].flags & 0x02 :  # SYN, respond with SYN+ACK
    synack = packet.copy()
    swap_src_and_dst(synack, Ether)
    swap_src_and_dst(synack, IP)
    tcp = synack[TCP]
    tcp.sport, tcp.dport = tcp.dport, tcp.sport 
    tcp.ack = packet[TCP].seq +1 
    tcp.seq = 0x1000
    tcp.flags |= 0x10    # add ACK
    synack[IP].chksum = None
    synack[TCP].chksum = None

    tun.write(synack.build() )

  elif packet.haslayer(TCP) and packet[TCP].flags & 0x10 and packet.haslayer(Raw) and len(packet[Raw].load) > 0 :  # data, echo it back
    ack = packet.copy()
    swap_src_and_dst(ack, Ether)
    swap_src_and_dst(ack, IP)
    tcp = ack[TCP]
    tcp.sport, tcp.dport = tcp.dport, tcp.sport 
    tcp.ack = packet[TCP].seq + len(packet[Raw].load) 
    tcp.seq = packet[TCP].ack

    # extract TCP's payload with packet[Raw].load
    ack[Raw].load = codecs.encode( ack[Raw].load, 'rot13')

    tcp.flags |= 0x10    # add ACK
    ack[IP].chksum = None
    ack[TCP].chksum = None

    tun.write(ack.build() )
  elif packet.haslayer(IPv6) :    # ignore it
    pass
  else:      # just print the packet. Use "packet.summary()" for one-line summary, "packet.show()" for detailed parse. 
    print "Unhandled packet: " + packet.summary()
  '''

  binary_packet = os.read(tun,tun.mtu)   # get packet routed to our "network"
  
  raw_packet = IP(binary_packet)        # Scapy parses byte string into its packet object
  
  print raw_packet.show()
