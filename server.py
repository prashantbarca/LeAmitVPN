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
import amitcrypto
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
        recv_info = ''
        send_info = ''
        
        while True:
            r, w, x = select.select(r, w, x)

            if self._tun in r:
                recv_packet = self._tun.read(mtu)
                print 'read'+ str(recv_packet)+ 'from tunnel'
                clientIP = IP(data)
                if clientIP:
                    send_addr = utils.get_public_ip(clientIP.dst)
                    recv_info = (send_addr,recv_packet)
                    print str(recv_packet)+' in queue'

            if self._sock in r:
                #xor = XOR.XORCipher(utils.key)
                data, addr =  self._sock.recvfrom(65535)
                data = utils.xor1.decrypt(data)
                auth = utils.recv_auth(self._sock, addr, data)
                exists = utils.check_if_addr_exists(addr)
                
                if exists != None:
                    # first get client address
                    clientIP = IP(data)
                    # authorization packet
                    if auth == True:
                        if clientIP:
                            # get message queue and send one by one
                            send_packets = utils.get_messages_for_client(clientIP.src)
                            if send_packets != None:
                                send_addr = get_public_ip(clientIP.src)
                                send_info = (send_addr,send_packets)
                                print ' '+str(send_packets)+' now in queue'
                    else:
                        utils.receive_non_auth_message(data)
                        if clientIP:
                            print 'sender: '+str(clientIP.src)+' receiver: '+str(clientIP.dst)
                            # add to queue for client
                            utils.message_for_client(clientIP.dst,data)
                            send_packets = utils.get_messages_for_client(clientIP.dst)
                            if send_packets != None:
                                send_addr = utils.get_public_ip(clientIP.dst)
                                send_info = (send_addr,send_packets)
                                print ' '+str(send_packets)+' now in queue'
                else:
                    # iptables forward
                    print ' addr '+ str(addr)+' does not exist .. iptables will forward the data:'+str(data)+ 'if it could'
                    raddr = addr[0]
                    rport = addr[1]
                    #xor = XOR.XORCipher(utils.key)
                    #self._sock.sendto(data,(raddr,rport))
                    self._sock.sendto(utils.xor.encrypt(data),(raddr,rport))

            if self._tun in w:
                print 'no encryption yet, writing to tunnel'
                # Encryption ?
                if send_info:
                    self._tun.write(send_info)
                    send_info = ''

            if self._sock in w:
                if recv_info:
                    raddr = recv_info[0][0]
                    rport = recv_info[0][1]
                    print 'writing to socket. This is meant for'+str(raddr)
                    
                    dirty_packets = recv_info[1]

                    for dirty_packet in dirty_packets:
                        #xor = XOR.XORCipher(utils.key)
                        #self._sock.sendto(dirty_packet, (raddr,rport))
                        self._sock.sendto(utils.xor.encrypt(dirty_packet), (raddr,rport))

                    utils.clear_messages(recv_info[0])
                    send_info = ''
                if recv_info:
                    
                    raddr = recv_info[0][0]
                    rport = recv_info[0][1]

                    self._sock.sendto(recv_info[1], (raddr,rport))

            r = []; w = []

            if send_info:
                w.append(self._tun)
            else:
                r.append(self._sock)
            if recv_info:
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
