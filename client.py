# Adapted from https://github.com/montag451/pytun/blob/master/test/test_tun.py

import sys
import optparse
import socket
from scapy.all import IP
import select
import errno
import pytun
import utils
import time
from threading import Thread
import signal
import md5
from Crypto.Cipher import XOR

def signal_handler(signal, frame):
    print('You pressed Ctrl+C!')
    sys.exit(0)

class TunnelClient(object):

    def __init__(self, taddr, tdstaddr, tmask, tmtu, laddr, lport, raddr, rport, rpw):
        self._tun = pytun.TunTapDevice("leamit0",flags=pytun.IFF_TUN|pytun.IFF_NO_PI)
        self._tun.addr = taddr
        self._tun.dstaddr = tdstaddr
        self._tun.netmask = tmask
        self._tun.mtu = tmtu
        self._tun.up()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((laddr, lport))
        self._raddr = raddr
        self._rport = rport
        self._rpw = md5.new(rpw).digest()
        if self._rpw != utils.users[self._tun.addr]:
            print "Password doesn't match"
            sys.exit(0)
        self._interval = 5 # 5 seconds is the timer interval
        self._time = 0

    def every_five_seconds(self):
        while True:
            utils.send_auth_packet(self._sock, self._tun.addr, self._rpw)
            time.sleep(5)
    
    def run(self):
        thread = Thread(target = self.every_five_seconds)
        thread.daemon = True
        thread.start()
        mtu = self._tun.mtu
        r = [self._tun, self._sock]; w = []; x = []
        data = ''
        to_sock = ''

        while True:
            try:
                # check if we need to fire a poll
                #cur_time = time.time()
                #if cur_time - self._time > 5:
                    #print 'sending auth'
                    #utils.send_auth_packet(self._sock, self._tun.addr, utils.users[self._tun.addr])
                    #self._time = time.time()

                r, w, x = select.select(r, w, x)
                
                if self._tun in r:
                    to_sock = self._tun.read(mtu)
                    print 'read'+str(to_sock)+ 'from tunnel'
                    
                if self._sock in r:
                    data, addr = self._sock.recvfrom(65535)
                    #aesobj = amitcrypto.AESCipher(key)
                    #data = aesobj.decrypt(data)
                    #data = aesobj.decrypt(data)
                    print 'received ' + data
                    if addr[0] != self._raddr or addr[1] != self._rport:
                        data = '' # drop packet
                if self._tun in w:
                    print 'writing to tunnel'
                    self._tun.write(data)
                    data = ''
                if self._sock in w:
                    print 'writing to socket'
                    #to_sock = "test"+to_sock+"test"
                    self._sock.sendto(to_sock, (self._raddr, self._rport))
                    to_sock = ''
                        
                r = []; w = []
                if data:
                    w.append(self._tun)
                else:
                    r.append(self._sock)
                if to_sock:
                    w.append(self._sock)
                else:
                    r.append(self._tun)
            except (select.error, socket.error, pytun.Error), e:
                if e[0] == errno.EINTR:
                    continue
                print >> sys.stderr, str(e)
                break

def main():
    signal.signal(signal.SIGINT, signal_handler)
    parser = optparse.OptionParser()
    parser.add_option('--tun-addr', dest='taddr',
            help='set tunnel local address')
    parser.add_option('--tun-dstaddr', dest='tdstaddr',
            help='set tunnel destination address')
    parser.add_option('--tun-netmask', default='255.255.255.0',dest='tmask',
            help='set tunnel netmask')
    parser.add_option('--pw', dest='pw',
            help='set password with pw')

    tun_mtu = 1500
    remote_addr = "128.199.177.106"
    remote_port = 5050
    
    parser.add_option('--local-addr', default='0.0.0.0', dest='laddr',
            help='set local address [%default]')
    parser.add_option('--local-port', type='int', default=12000, dest='lport',
            help='set local port [%default]')

    opt, args = parser.parse_args()
    if not (opt.taddr and opt.tdstaddr and opt.pw):
        parser.print_help()
        return 1
    try:
        server = TunnelClient(opt.taddr, opt.tdstaddr, opt.tmask, tun_mtu,
                              opt.laddr, opt.lport, remote_addr, remote_port, opt.pw)
    except (pytun.Error, socket.error), e:
        print >> sys.stderr, str(e)
        return 1
    server.run()
    return 0

if __name__ == '__main__':
    sys.exit(main())

