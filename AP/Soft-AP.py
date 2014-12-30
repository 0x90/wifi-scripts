#!/usr/bin/env python
# -*- coding: Utf-8 -*-

__app__ = 'SoftAP Maker'
__verions__ = '0.3'
__author__ = 'MatToufoutu'

import os
from sys import exit as sysexit
from commands import getoutput
from threading import Thread
from time import sleep

def airBase(bssid, essid, channel, iface):
    os.system("modprobe tun 2>&1 1>& /dev/null")
    os.system("xterm -e airbase-ng -a %s -e '%s' -c %s %s" % (bssid, essid, channel, iface))

#CHECK IF USER IS ROOT
if getoutput('whoami') != 'root':
    print("You have to be root!")
    sysexit()

os.system("clear")
print("\n\t\t\t[ SoftAP Maker ]")

# GET SETTINGS FOR THE FAKE AP
IFACE, BSSID, ESSID, CHANNEL = '', '', '', 0
DHCPDCONF="""
## This configuration was auto-generated for SoftAP
ddns-update-style ad-hoc;
default-lease-time 600;
max-lease-time 7200;
subnet 10.0.0.0 netmask 255.255.255.0 {
    option subnet-mask 255.255.255.0;
    option broadcast-address 10.0.0.255;
    option routers 10.0.0.1;
    option domain-name-servers 208.67.222.222, 208.67.220.220;
    range 10.0.0.10 10.0.0.20;
}
## End of SoftAP auto-generated config
"""

IFACE = raw_input("\nWireless interface to use\n>>> ")
while IFACE not in getoutput('iwconfig'):
    print("Interface %s can't be found, please try again\n" % IFACE)
    IFACE = raw_input("Wireless interface to use\n>>> ")
if not 'Monitor' in getoutput('iwconfig '+IFACE).splitlines()[0] \
and not 'Monitor' in getoutput('iwconfig '+IFACE).splitlines()[1]:
    print("Switching interface to Monitor Mode")
    os.system('airmon-ng start '+IFACE+' > /dev/null')
    if not 'Monitor' in getoutput('iwconfig '+IFACE).splitlines()[0] \
    and not 'Monitor' in getoutput('iwconfig '+IFACE).splitlines()[1]:
        print("Could not switch interface to monitor mode")
        print("If your interface use VAPs, specify directly your monitor interface")
        sysexit()

OUT_IFACE = raw_input("\nInternet connection interface\n>>> ")
while OUT_IFACE not in getoutput('ifconfig'):
    print("Interface %s can't be found, please try again\n>>> " % OUT_IFACE)
    OUT_IFACE = raw_input("Internet connection interface\n>>> ")

BSSID = raw_input("\nFake AP's BSSID (leave blank to use card's @mac)\n>>> ")
while (len(BSSID) != 17) and (BSSID.count(':') != 5):
    if BSSID == '':
        BSSID = getoutput('macchanger -s '+IFACE+" | awk '{print $3}'")
        break
    print("BSSID %s in not valid. Please try again" % BSSID)
    BSSID = raw_input("Fake AP's BSSID (leave blank to use card's @mac)\n>>> ")

ESSID = raw_input("\nFake AP's ESSID\n>>> ")
while ESSID == '':
    print("You MUST enter an ESSID for your Fake AP")
    ESSID = raw_input("Fake AP's ESSID\n>>> ")

CHANNEL = raw_input("\nChannel to use\n>>> ")
while not CHANNEL.isdigit() and not (0 < int(CHANNEL) < 14):
    print("Channel %s is not valid. It must be 1 to 13. Please try again")
    CHANNEL = raw_input("Channel to use\n>>> ")

#SETUP FAKE AP
print("\n\nStarting airbase-ng in a separate window")
fakeAP = Thread(None, airBase, None, (BSSID, ESSID, CHANNEL, IFACE), {})
fakeAP.start()
sleep(3)
os.system('ifconfig at0 up && \
           ifconfig at0 10.0.0.1 netmask 255.255.255.0 && \
           ifconfig at0 mtu 1500 && \
           route add -net 10.0.0.0 netmask 255.255.255.0 gw 10.0.0.1')
configfile = open('dhcpd.conf', 'w')
configfile.write(DHCPDCONF)
configfile.close()
print("\nStarting DHCP server for SoftAP clients")
os.system('dhcpd -cf dhcpd.conf at0 || dhcpd3 -cf dhcpd.conf at0')
print("\nSetting up iptables and ip forwarding")
if os.path.exists(os.getcwd()+'/iptables.rules'):
    os.remove(os.getcwd()+'/iptables.rules')
os.system('iptables-save > iptables.rules && \
           iptables -F && iptables -X && iptables -Z && \
           iptables -t nat -F && iptables -t nat -X && iptables -t nat -Z && \
           echo 1 > /proc/sys/net/ipv4/ip_forward && \
           iptables -t nat --append POSTROUTING --out-interface %s -j MASQUERADE'
           % OUT_IFACE)
endAP = raw_input("\nPress <Enter> to stop the SoftAP")

#STOP AP AND RESTORE CONFIGURATIONS
print("Restoring all configurations")
dhcp_pid = getoutput("ps aux | grep -v grep | grep 'dhcpd -cf dhcpd.conf' | awk '{print $2}'")
airbase_pid = getoutput("ps aux | grep -v grep | grep airbase-ng | awk '{print $2}'")
os.system('kill -9 %s && killall airbase-ng && \
           iptables -t nat -F && iptables -t nat -X && iptables -t nat -Z && \
           iptables-restore < iptables.rules && \
           echo 0 > /proc/sys/net/ipv4/ip_forward' % dhcp_pid)
os.remove(os.getcwd()+'/dhcpd.conf')
os.remove(os.getcwd()+'/iptables.rules')
print("\nThanks for using SoftAP Maker\n")
sysexit()