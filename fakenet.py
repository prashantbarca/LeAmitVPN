#!/usr/bin/env python

#
#  All configs of the fake network go here
#

import subprocess 
import re           # for matching out MAC
import pytap

#
#   This interface will be the "gateway" into the fake network
#    NOTE: check if other routes for this network exist, warn & exit if so!
#
GW_MAC   = '02:02:03:04:05:01' # multicast bit: off, locally-administered bit: on
BASE_MAC = '02:02:03:04:05:'   #  same, less last byte
GW_IP    = '10.5.0.1'

def configure_iface(ifname, ether, ip, netmask = '255.255.255.0', bcast = ''):
    # Bring it down first
    subprocess.check_call("ifconfig %s down" % ifname, shell=True)

    hw_cfg_cmd = "ifconfig %s hw ether %s " % (ifname, ether)
    # Something causes this to fail on MacOS:
    try:
      subprocess.check_call( hw_cfg_cmd, shell=True)
    except:
      print "%s seems unsuppoted on this platform, skipping\n" % hw_cfg_cmd
      pass

    if bcast != '':
      ip_cfg_cmd = "ifconfig %s %s netmask %s broadcast %s up" % (ifname, ip, netmask, bcast)
    else:
      # ...and hope ifconfig is smart and computes bcast address! YMMV.
      ip_cfg_cmd = "ifconfig %s %s netmask %s up" % (ifname, ip, netmask)

    subprocess.check_call( ip_cfg_cmd, shell=True)

#  Configure given tap device to be on the fake network
#
def configure_tap(ifname):
    configure_iface(ifname, GW_MAC, GW_IP)

def fake_mac_for_ip(ip):
    s1, s2, s3, s4 = ip.split('.')
    return BASE_MAC + ("%02x" % int(s4))  

def get_gw_ip():
    return GW_IP

def get_fake_mac(iface):
    out=subprocess.check_output( "ifconfig " + iface, shell=True)
    r = re.compile( 'ether (\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)' )
    m = r.search( out )
    return m.group(1)
