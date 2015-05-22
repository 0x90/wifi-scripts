#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from os import path
from scapy.all import *

sniff('en1', prn=lambda x: hexdump(x))
sniff("en1", prn=lambda x: x.summary())



sniff('en1', lfilter=lambda x: x.haslayer(Dot11ProbeReq), prn=lambda x: hexdump(x))
sniff('en1', lfilter=lambda x: x.haslayer(Dot11ProbeReq), prn=lambda x: x.info)
sniff('en1', lfilter=lambda x: x.haslayer(Dot11ProbeReq), prn=lambda x: (x.addr1, x.addr2, x.addr3,x.info))
sniff('en1', lfilter=lambda x: x.haslayer(Dot11ProbeReq), prn=lambda x: ( x.addr2, x.info))
sniff('en1', lfilter=lambda x: x.haslayer(Dot11ProbeReq), prn=lambda x: ( x.addr2, x.info, x.Rate))

sniff('en1', lfilter=lambda x: x.haslayer(Dot11Beacon), prn=lambda x: hexdump(x))
sniff('en1', lfilter=lambda x: x.haslayer(Dot11Beacon) , prn=lambda x: x.info)
sniff('en1', lfilter=lambda x: x.haslayer(Dot11Beacon) , prn=lambda p: p.info, store=0)

set(map(lambda x: (x.addr2,x.info),sniff('en1', timeout=3, lfilter=lambda x: x.haslayer(Dot11Beacon))))
set(map(lambda x: (x.addr2,x.info),sniff('en1', timeout=3, lfilter=lambda x: x.haslayer(Dot11Beacon))))
set(filter(lambda x: '\x00' not in x[1], map(lambda x: (x.addr2,x.info),sniff('en1', timeout=3, lfilter=lambda x: x.haslayer(Dot11Beacon)))))

sniff('en1', lfilter=lambda x: x.haslayer(Dot11Beacon), prn=lambda x: ls(x))


sniff('en1', lfilter=lambda x: x.haslayer(Dot11Beacon)).make_table( lambda x: (x.addr2, x.info) )
sniff("en1", prn=lambda x:x.sprintf("{Dot11Beacon:%Dot11.addr3%\t%Dot11Beacon.info%\t%PrismHeader.channel%\tDot11Beacon.cap%}"))
 sniff("en1",lfilter=lambda x: x.haslayer(Dot11Beacon), prn=lambda x: x[Dot11Beacon].cap)