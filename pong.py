#!/usr/bin/env python

#
#  Fake ICMP and ARP responses from non-existings IPs via tap0.
#   Create fake MAC addresses on the fly.
#

from scapy.all import *

import os

import pytap    # my pytab wrapper around basic system-specific syscalls
import fakenet  # configs & methods for the fake network to emulate

tun, ifname = pytap.open('tap0') 
print "Allocated interface %s. Configuring it." % ifname
fakenet.configure_tap(ifname) 

# About-face for a packet: swap src and dst in specified layer
def swap_src_and_dst(pkt, layer):
  pkt[layer].dst, pkt[layer].src = pkt[layer].src, pkt[layer].dst 

#
#  Now process packets
#
while 1:
  binary_packet = os.read(tun, 2048)   # get packet routed to our "network"
  packet = Ether(binary_packet)        # Scapy parses byte string into its packet object


  if packet.haslayer(ICMP) and packet[ICMP].type == 8 : # ICMP echo-request
    pong = packet.copy() 
    swap_src_and_dst(pong, Ether)
    swap_src_and_dst(pong, IP)
    pong[ICMP].type='echo-reply'
    pong[ICMP].chksum = None   # force recalculation
    pong[IP].chksum   = None
    os.write(tun, pong.build())  # send back to the kernel

  elif packet.haslayer(ARP) and packet[ARP].op == 1 : # ARP who-has
    arp_req = packet;  # don't need to copy, we'll make reply from scratch

    # make up a new MAC for every IP address, using the address' last octet 
    fake_src_mac = fakenet.fake_mac_for_ip(arp_req.pdst)

    # craft an ARP response
    arp_rpl = Ether(dst=arp_req.hwsrc, src=fake_src_mac)/ARP(op="is-at", psrc=arp_req.pdst, pdst=fakenet.get_gw_ip(), hwsrc=fake_src_mac, hwdst=arp_req.hwsrc)
    os.write(tun, arp_rpl.build() ) # send back to kernel

  else:      # just print the packet. Use "packet.summary()" for one-line summary
    print "Unknown packet: "
    print packet.summary()
