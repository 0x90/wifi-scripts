from scapy.all import *
import dpkt
import binascii
from pprint import *

interface = "mon0"
observedclients = []


def sniffmgmt(p):
    if p.haslayer(Dot11):
        rawdata = p.build()
        tap = dpkt.radiotap.Radiotap(rawdata)
        #pprint(tap)
        if hasattr(tap, "ant_sig"):
            signal_ssi = -(256 - tap.ant_sig.db)  # Calculate signal strength
        else:
            signal_ssi = 0
        if hasattr(tap, "channel"):
            channel = tap.channel
        else:
            channel = 0

        t_len = binascii.hexlify(rawdata[2:3])  # t_len field indicates the entire length of the radiotap data, including the radiotap header.
        t_len = int(t_len, 16)  # Convert to decimal
        #pprint(t_len)
        wlan = dpkt.ieee80211.IEEE80211(rawdata[t_len:])
        #pprint(tap.data)
        #wlan = dpkt.ieee80211.IEEE80211(tap.data.data)

        if wlan.type == 0 and wlan.subtype == 8:  # Indicates a beacon
            #pprint(wlan)
            if hasattr(wlan, "ies"):
                if hasattr(wlan.ies, "info"):
                    ssid = wlan.ies[0].info
                else:
                    ssid = ''
            else:
                ssid = ''
            mac = binascii.hexlify(wlan.mgmt.src)
            print "%s, %s (%d dBm) %d" % (mac, ssid, signal_ssi, int(channel.freq))  # With the sniffmgmt() function complete, we can invoke the Scapy sniff()  # function, pointing to the monitor mode interface, and telling Scapy to call


sniff(iface=interface, prn=sniffmgmt)

