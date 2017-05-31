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
import utils
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
        recv_packet = ''
        send_info = ''
        
        while True:
            r, w, x = select.select(r, w, x)

            if self._tun in r:
                recv_packet = self._tun.read(mtu)

            if self._sock in r:
                data =  self._sock.recv(65535)

                raw_data = Raw(data)

                if raw_data != None:
                    raw_data = raw_data.show()
                    raw_str = raw_data.snprintf("{Raw.load}")

                    if raw_str!= None and raw_str.find("username") != -1:
                        auth = recv_auth(self._sock, addr, raw_data)
                        if auth == True:
                            # get message queue and send one by one
                            send_packets = utils.get_message_queue(addr)
                            send_info = (addr,send_packets)
                        else:
                            send_info = ''

            if self._tun in w:
                # Encryption ?
                self._tun.write(send_info)
                send_info = ''

            if self._sock in w:
                raddr = send_info[0][0]
                rport = send_info[0][1]
                dirty_packets = send_info[1]
                
                for dirty_packet in dirty_packets:
                    self._sock.sendto(dirty_packet,(raddr,rport))
                    
                send_info = ''

            r = []; w = []

            if data:
                w.append(self._tun)
            else:
                r.append(self._sock)
            if to_sock:
                w.append(self._sock)
            else:
                r.append(self._tun)

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
