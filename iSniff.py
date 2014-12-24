#!/usr/bin/env python
# Tiny WiFi sniffer for Apple AirPort card.
# Based on https://gist.githubusercontent.com/nevdull77/10605115/raw/a2c10a3fee579b1e64404ac1266ca24589e4d3f5/sniff.py
# http://www.cqure.net/wp/2014/04/scapy-with-wifi-monitor-rfmon-mode-on-os-x/#more-553
# This insight was included in airoscapy.py (http://www.thesprawl.org/projects/airoscapy/)

from scapy.all import *
from scapy.layers.dot11 import *
from datetime import datetime
from time import time
from pprint import pprint
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

__author__ = '090h'
__license__ = 'GPL'

PROBE_REQUEST_TYPE = 0
PROBE_REQUEST_SUBTYPE = 4

class iSniffer(object):


    def __init__(self, iface='en1', whitelist=None, verbose=False):
        # Replace this with your phone's MAC address
        if not whitelist: whitelist = ['00:00:00:00:00:00', ]
        self.iface = iface
        self.whitelist = whitelist
        self.verbose = verbose
        self.aps = {}
        self.clients = {}

    # Probe requests from clients
    def handle_probe(self, pkt):
        if pkt.haslayer(Dot11ProbeReq) and '\x00' not in pkt[Dot11ProbeReq].info:
            essid = pkt[Dot11ProbeReq].info
        else:
            essid = 'Hidden SSID'
        client = pkt[Dot11].addr2

        if client in self.whitelist or essid in self.whitelist:
            #TODO: add logging
            return

        # New client
        if client not in self.clients:
            self.clients[client] = []
            print('[!] New client:  %s ' % client)

        if essid not in self.clients[client]:
            self.clients[client].append(essid)
            print('[+] New ProbeRequest: from %s to %s' % (client, essid))

    def handle_beacon(self, pkt):
        if not pkt.haslayer(Dot11Elt):
            return

        # Check to see if it's a hidden SSID
        essid = pkt[Dot11Elt].info if '\x00' not in pkt[Dot11Elt].info and pkt[Dot11Elt].info != '' else 'Hidden SSID'
        bssid = pkt[Dot11].addr3
        client = pkt[Dot11].addr2

        if client in self.whitelist or essid in self.whitelist or bssid in self.whitelist:
            #TODO: add logging
            return

        try:
            channel = int(ord(pkt[Dot11Elt:3].info))
        except:
            channel = 0

        try:
            extra = pkt.notdecoded
            rssi = -(256-ord(extra[-4:-3]))
        except:
            rssi = -100
            #print "No signal strength found"

        p = pkt[Dot11Elt]

        capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                          "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
        # print('capability = %s' % capability)

        crypto = set()
        while isinstance(p, Dot11Elt):
            if p.ID == 48:
                crypto.add("WPA2")
            elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
                crypto.add("WPA")
            p = p.payload

        if not crypto:
            if 'privacy' in capability:
                crypto.add("WEP")
            else:
                crypto.add("OPN")

        # print "NEW AP: %r [%s], channed %d, %s" % (ssid, bssid, channel,' / '.join(crypto))
        # print "Target: %s Source: %s SSID: %s RSSi: %d" % (pkt.addr3, pkt.addr2, pkt.getlayer(Dot11ProbeReq).info, rssi)
        enc = '/'.join(crypto)
        if bssid not in self.aps:
            self.aps[bssid] = (channel, essid, bssid, enc, rssi)
            print "[+] New AP {0:5}\t{1:20}\t{2:20}\t{3:5}\t{4:4}".format(channel, essid, bssid, enc, rssi)


    def pkt_handler(self, pkt):
        # wlan.fc.type == 0           Management frames
        # wlan.fc.type == 1           Control frames
        # wlan.fc.type == 2           Data frames
        # wlan.fc.type_subtype == 0   Association request
        # wlan.fc.type_subtype == 1   Association response
        # wlan.fc.type_subtype == 2   Reassociation request
        # wlan.fc.type_subtype == 3   Reassociation response
        # wlan.fc.type_subtype == 4   Probe request
        # wlan.fc.type_subtype == 5   Probe response
        # wlan.fc.type_subtype == 8   Beacon
        #
        # if pkt.type == 0 and pkt.subtype == 8:
        #     if '\x00' in pkt.info:
        #         essid = ''
        #     else:
        #         essid = pkt.info
        #     print "AP MAC: %s with SSID: %s " % (pkt.addr2, essid)
        #
        # if pkt.type == 0 and pkt.subtype == 4:
        #     self.handle_probe(pkt)
        #
        # return
            #if pkt.addr2 not in ap_list :
            #ap_list.append(pkt.addr2)
            #print "AP MAC: %s with SSID: %s " % (pkt.addr2, pkt.info)
        #print('Type: %i Subtype: %i' % (pkt.type, pkt.subtype))
        # print(pkt.summary)
        # return

        # Client ProbeReq
        # if pkt.haslayer(Dot11ProbeReq):
        if pkt.type == PROBE_REQUEST_TYPE and pkt.subtype == PROBE_REQUEST_SUBTYPE:
            self.handle_probe(pkt)

        # AP beacon or response
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            self.handle_beacon(pkt)

    def sniff(self, count=0):
        '''
        Sniff Beacon and Probe Requst/Response frames to extract AP info
        :param count: packets to capture, 0 = loop
        :return:
        '''
        print('Press Ctrl-C to stop sniffing.')
        sniff(iface=self.iface,
              prn=self.pkt_handler,
              # lfilter=lambda p: p.haslayer(Dot11))
              lfilter=lambda p: p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp) or p.haslayer(Dot11ProbeReq))

    def stat(self):
        # Print results
        print('\nAP list:')
        pprint(self.aps)
        print('Clients:')
        pprint(self.clients)


        # make_table(lambda l:"%%-%is" % l, lambda l:"%%-%is" % l, "", *args, **kargs)
        #make_table(self.ap.items(), lambda l: str(l))
        # lambda l: ",".join(['"%s"' % x for x in [self.ap[l]['ssid'], self.ap[l]['cli'], self.ap[l]['lastseen']]]))
        # print(",".join(["ssid", "cli", "lastseen"]))
        # for key in self.ap:
        # print(",".join(['"%s"' % x for x in [self.ap[key]['ssid'], self.ap[key]['cli'], self.ap[key]['lastseen']]]))


if __name__ == '__main__':
    parser = ArgumentParser('iSniff', description='Tiny iSniff for RFMON under OS X',
                            formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('-i', '--interface', default='en1', required=False, help='Interface to used')
    args = parser.parse_args()

    isniff = iSniffer(args.interface)
    isniff.sniff()
    isniff.stat()
