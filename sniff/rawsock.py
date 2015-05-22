#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Linux raw socket 802.11 sniffer
# Usage:
# sudo ./rawsock.py mon0

import socket
import sys

def sniff_raw_socket(iface):
    rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    rawSocket.bind((iface, 0x0003))
    ap_list = set()
    while True:
        pkt = rawSocket.recvfrom(2048)[0]
        if pkt[26] == "\x80":
            if pkt[36:42] not in ap_list and ord(pkt[63]) > 0:
                ap_list.add(pkt[36:42])
                print("SSID: %s  AP MAC: %s" % (pkt[64:64 +ord(pkt[63])], pkt[36:42].encode('hex')))

if __name__ == '__main__':
    if len(sys.argv) == 1:
        print('Usage:\nsudo ./rawsock.py mon0')
        sys.exit(-1)

    sniff_raw_socket(sys.argv[1])