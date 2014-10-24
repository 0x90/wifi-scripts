#!/usr/bin/env python
# -*- encoding: utf-8 -*-
from sys import argv
import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0

def sniff_dummy(iface):
    def handler(x):
        return x.sprintf("{Dot11Beacon:%Dot11.addr3%\t%Dot11Beacon.info%\t%PrismHeader.channel%\tDot11Beacon.cap%}")
    sniff(iface=iface, prn=handler)

def sniff_raw_socket(iface):
    rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    rawSocket.bind((iface, 0x0003))
    ap_list = set()
    while True:
        pkt = rawSocket.recvfrom(2048)[0]
        if pkt[26] == "\x80":
            if pkt[36:42] not in ap_list and ord(pkt[63]) > 0:
                ap_list.add(pkt[36:42])
                print "SSID: %s  AP MAC: %s" % (pkt[64:64 +ord(pkt[63])], pkt[36:42].encode('hex'))

def sniff_dummy2(iface):
    ap_list = []
    def handler(pkt):
        if pkt.haslayer(Dot11) :
            if pkt.type == 0 and pkt.subtype == 8 :
                if pkt.addr2 not in ap_list :
                    ap_list.append(pkt.addr2)
                    print "AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)

    sniff(iface="mon0", prn=handler)




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
            if pkt.haslayer(Dot11ProbeReq) and '\x00' not in pkt[Dot11ProbeReq].info:
                essid = pkt[Dot11ProbeReq].info
            else:
                # essid = 'Hidden SSID'
                essid = None
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

