#!/usr/bin/env python
from sys import argv

sniff(iface=argv[1],
    prn=lambda x:x.sprintf("{Dot11Beacon:%Dot11.addr3%\t%Dot11Beacon.info%\t%PrismHeader.channel%\tDot11Beacon.cap%}"))