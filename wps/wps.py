#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from sys import argv
from PyLorcon2 import Context
from threading import Thread
from time import sleep
import signal
from subprocess import Popen, PIPE

# import scapy silently
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0


class Hopper(Thread):
    def __init__(self, iface):
        super(Hopper, self).__init__()
        self.daemon = True
        self._stop = False

        self.iface = iface
        self.ctx = Context(iface)
        self.ctx.open_monitor()
        # self.ctx.open_injmon()

    def __del__(self):
        self.ctx.close()

    def run(self, channels=None, wait=1):
        if channels is None:
            channels = [1, 6, 11]
        i = 0
        while not self._stop:
            c = channels[i]
            print("Switching to %s channel: %i" % (self.iface, c))
            # self.ctx.set_channel(c)
            proc = Popen(['iw', 'dev', self.iface, 'set', 'channel', c], stdout=DN, stderr=PIPE)
            i = (i + 1) % len(channels)
            sleep(wait)

    def stop(self):
        logging.debug('Stopping thread: %s..' % self.name)
        self._stop = True


class WiFiSniffer():
    def __init__(self, iface):
        self.iface = iface
        self.hopper = Hopper(iface)
        self.ap_dict = {}

    def handle_beacon(self, pkt):
        # if not pkt.haslayer(Dot11Elt):
        # return

        # Check to see if it's a hidden SSID
        essid = pkt[Dot11Elt].info if '\x00' not in pkt[Dot11Elt].info and \
                                      pkt[Dot11Elt].info != '' else 'Hidden SSID'
        bssid = pkt[Dot11].addr3
        client = pkt[Dot11].addr2

        try:
            channel = int(ord(pkt[Dot11Elt:3].info))
        except:
            channel = 0

        try:
            extra = pkt.notdecoded
            rssi = -(256 - ord(extra[-4:-3]))
        except:
            rssi = -100
            # print "No signal strength found"

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
        if bssid not in self.ap_dict:
            self.ap_dict[bssid] = (channel, essid, bssid, enc, rssi)
            print "[+] New AP {0:5}\t{1:20}\t{2:20}\t{3:5}\t{4:4}".format(channel, essid, bssid, enc, rssi)

    def signal_handler(self, signal, frame):
        print('You pressed Ctrl+C! Exiting...')
        print('Stopping hopper')
        self.hopper.stop()

    def run(self, channels=None, wait=1):
        print('Launching hopper thread')
        self.hopper.start()

        print('Press Ctrl-C to stop sniffing.')
        sniff(iface=self.iface, prn=self.handle_beacon,
              lfilter=lambda p: p.haslayer(Dot11Beacon) and p.haslayer(Dot11Elt))

if __name__ == '__main__':
    if len(argv) == 1:
        print('Usage:\n\t./scan.py <iface>')
    else:
        ws = WiFiSniffer(argv[1])
        ws.run()