#!/usr/bin/env python

from scapy.all import *
from sys import argv, exit

# def fake_ap_2(iface, ssid, pkt_count=0):
#     pkt = Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=RandMAC(),addr3=RandMAC())/
#         Dot11Beacon(cap="ESS")/
#         Dot11Elt(ID="SSID",info='I should see this')/
#         Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16')/
#         Dot11Elt(ID="DSset",info="\x03")/
#         Dot11Elt(ID="TIM",info="\x00\x01\x00\x00")
#
#     sendp(pkt, iface=iface, loop=1)

def fake_ap(iface, ssid, loop=1,):
    sendp(RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3=RandMAC())/
    # send(Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3=RandMAC())/
          Dot11Beacon(cap="ESS")/
          Dot11Elt(ID="SSID",info=ssid)/
          Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16')/
          Dot11Elt(ID="DSset",info="\x03")/
          Dot11Elt(ID="TIM",info="\x00\x01\x00\x00"), iface=iface, loop=loop)

if __name__ == '__main__':
    if len(argv) == 1:
        print('Specify interface. Example: ./ap-scapy.py wlan2')
        exit(0)

    fake_ap(argv[1], 'HackSSID')