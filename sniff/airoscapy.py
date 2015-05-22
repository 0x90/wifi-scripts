#!/usr/bin/env python
# airoscapy.py - Wireless AP scanner based on scapy
# version: 0.2
# Author: iphelix
import sys, os, signal
from multiprocessing import Process

from scapy.all import *

interface='' # monitor interface
aps = {} # dictionary to store unique APs

# process unique sniffed Beacons and ProbeResponses. 
def sniffAP(p):
    if ( (p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)) 
                 and not aps.has_key(p[Dot11].addr3)):
        ssid       = p[Dot11Elt].info
        bssid      = p[Dot11].addr3    
        channel    = int( ord(p[Dot11Elt:3].info))
        capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        
        # Check for encrypted networks
        if re.search("privacy", capability): enc = 'Y'
        else: enc  = 'N'

        # Save discovered AP
        aps[p[Dot11].addr3] = enc

        # Display discovered AP    
        print "%02d  %s  %s %s" % (int(channel), enc, bssid, ssid) 

# Channel hopper
def channel_hopper():
    while True:
        try:
            channel = random.randrange(1,15)
            os.system("iw dev %s set channel %d" % (interface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break

# Capture interrupt signal and cleanup before exiting
def signal_handler(signal, frame):
    p.terminate()
    p.join()

    print "\n-=-=-=-=-=  STATISTICS =-=-=-=-=-=-"
    print "Total APs found: %d" % len(aps)
    print "Encrypted APs  : %d" % len([ap for ap in aps if aps[ap] =='Y'])
    print "Unencrypted APs: %d" % len([ap for ap in aps if aps[ap] =='N'])

    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage %s monitor_interface" % sys.argv[0]
        sys.exit(1)

    interface = sys.argv[1]

    # Print the program header
    print "-=-=-=-=-=-= AIROSCAPY =-=-=-=-=-=-"
    print "CH ENC BSSID             SSID"

    # Start the channel hopper
    p = Process(target = channel_hopper)
    p.start()

    # Capture CTRL-C
    signal.signal(signal.SIGINT, signal_handler)

    # Start the sniffer
    sniff(iface=interface,prn=sniffAP)
