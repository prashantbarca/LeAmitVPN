#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2017 prashant <prashant@prashant>
#
# Distributed under terms of the MIT license.


# Adapted:
# https://github.com/montag451/pytun/blob/master/test/test_tun.py and
# https://github.com/sergeybratus/netfluke/blob/master/tcp.py

import sys
import optparse
import socket
import select
import errno
import pytun
import regex
from scapy.all import IP,UDP,Raw

def swap_src_and_dst(pkt, layer):
    pkt[layer].dst, pkt[layer].src = pkt[layer].src, pkt[layer].dst 

class TunnelServer(object):

    def __init__(self, taddr, tdstaddr, tmask, tmtu, laddr, lport):
        
        self._tun = pytun.TunTapDevice("leamit0",flags=pytun.IFF_TUN|pytun.IFF_NO_PI)
        self._tun.addr = taddr
        self._tun.dstaddr = tdstaddr
        self._tun.netmask = tmask
        self._tun.mtu = tmtu
        self._tun.up()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((laddr, lport))

    def run(self):
        mtu = self._tun.mtu
        r = [self._tun, self._sock]; w = []; x = []
        data = ''
        to_sock = ''
        while True:
            r, w, x = select.select(r, w, x)
            if self._tun in r:
                to_sock = self._tun.read(mtu)
            if self._sock in r:
                data, addr = self._sock.recvfrom(65535)
                self._raddr = addr[0]
                self._rport = addr[1]
                raw_data = Raw(data)
                if raw_data != None:
                    raw_data = raw_data.show()
                    raw_str = raw_data.snprintf("{Raw.load}")

                    if raw_str!= None and raw_str.find("username") != -1:
                        recv_auth(self._sock, addr, raw_data)
                
            if self._tun in w:
                #self._tun.write(data)
                data = ''
            if self._sock in w:
                #to_sock = "test"+to_sock+"test"
                #self._sock.sendto(to_sock, (self._raddr, self._rport))
                to_sock = ''

            #r = []; w = []

            #if data:
            #    w.append(self._tun)
            #else:
            #    r.append(self._sock)
            #if to_sock:
            #    w.append(self._sock)
            #else:
            #    r.append(self._tun)
                    
def main():
    tun_mtu = 1500

    ptp_addr = "10.10.0.1"
    ptp_dst = "10.10.0.0"
    ptp_mask = "255.255.255.0"
    sock_addr = "128.199.177.106"
    sock_port = 5050

    server = TunnelServer(ptp_addr, ptp_dst, ptp_mask, tun_mtu,
                              sock_addr, sock_port)
    server.run()
    return 0

if __name__ == '__main__':
    sys.exit(main())
