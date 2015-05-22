#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# 802.11 sniffer/wpsig/wpspin/reaver
# Credits go to:
#
# Craig Heffner Tactical Network Solutions
# https://github.com/devttys0/wps
#
# WPSIG [ablanco@coresecurity.com, oss@coresecurity.com]

from sys import argv, exit
from os import path, geteuid

# import logging
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# from scapy.all import conf
# conf.verb = 1
# conf.use_pcap = True
# conf.use_dnet = False

from scapy.layers.dot11 import *
from scapy.all import *


# impacket
try:
    from impacket import dot11
    from impacket.dot11 import Dot11
    from impacket.dot11 import Dot11Types
    from impacket.dot11 import Dot11ManagementFrame
    from impacket.dot11 import Dot11ManagementProbeRequest
    from impacket.ImpactDecoder import RadioTapDecoder
except ImportError:
    Exception("impacket")

from pprint import pprint
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter


if LINUX:
    # print('Linux detected. Trying to import PyLorcon2...')
    try:
        import PyLorcon2
    except ImportError:
        logging.warning('PyLorcon2 import failed. Injection is not available.')

if WINDOWS:
    logging.error('Sorry, no Windows.')
    exit(-1)

if DARWIN:
    logging.warning('OS X detected. Only pasive mode will be available')

#TODO: add iOS and Android detection



PROBE_REQUEST_TYPE = 0
PROBE_REQUEST_SUBTYPE = 4


class WiFiWizard(object):


    def __init__(self, iface, output=None, whitelist=None, verbose=False):
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


        try:
            print('-->', pkt.name)
        except:
            pass

        #Beacon
        if pkt.haslayer(Dot11Beacon):
            self.handle_beacon(pkt)

        # Client ProbeReq
        if pkt.haslayer(Dot11ProbeReq):
            self.handle_request(pkt)

        # if pkt.type == PROBE_REQUEST_TYPE and pkt.subtype == PROBE_REQUEST_SUBTYPE:

        if pkt.haslayer(Dot11ProbeResp):
            self.handle_response(pkt)



    def sniff(self):
        '''
        Sniff Beacon and Probe Requst/Response frames to extract AP info
        :param count: packets to capture, 0 = loop
        :return:
        '''
        print('Press Ctrl-C to stop sniffing.')
        sniff(iface=self.iface,
              prn=self.pkt_handler,
              lfilter=lambda p: p.haslayer(Dot11))

if __name__ == '__main__':
    parser = ArgumentParser(description='WiFi PWN T00L', formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    parser.add_argument('interface',  help='802.11 interface to use')
    parser.add_argument('-c', '--channel', required=False)
    parser.add_argument('-w', '--wps', required=False, action='store_true', help='wps hack')
    parser.add_argument('-a', '--active', required=False, action='store_true', help='active mode')

    args = parser.parse_args()

    if geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'.")

    WiFiWizard(args.interface).sniff()

