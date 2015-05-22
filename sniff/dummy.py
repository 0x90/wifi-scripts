#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Dummy 802.11 sniffer

from sys import argv
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon
conf.verb = 0


def sniff_dummy(iface):
    ap_list = []

    def handler(pkt):
        if pkt.haslayer(Dot11) and pkt.haslayer(Dot11Beacon):
            if pkt.addr2 not in ap_list:
                ap_list.append(pkt.addr2)
                print("AP MAC: %s with SSID: %s " % (pkt.addr2, pkt.info))

    sniff(iface=iface, prn=handler)


if __name__ == '__main__':
    sniff_dummy(argv[1])
