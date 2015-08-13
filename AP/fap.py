#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# FAP - FAP - FAP - FAP
#  Fuzzing Access Point
# FAP - FAP - FAP - FAP

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from os import path
from subprocess import Popen, PIPE
from threading import Thread, Lock
import os
import time
import sys
import re
import signal
import argparse
import logging
import socket
import struct
import fcntl


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan

lock = Lock()
DN = open(os.devnull, 'w')
APs = {} # for listing APs
chan = 0 # for channel hopping Thread
count = 0 # for channel hopping Thread
forw = '0\n' # for resetting ip forwarding to original state
ap_mac = '' # for sniff's cb function
err = None # check if channel hopping is working



def channel_hop(mon_iface):
    global chan, err
    while 1:
        try:
            err = None
            if chan > 11:
                chan = 0
            chan = chan+1
            channel = str(chan)
            iw = Popen(['iw', 'dev', mon_iface, 'set', 'channel', channel], stdout=DN, stderr=PIPE)
            for line in iw.communicate()[1].split('\n'):
                if len(line) > 2: # iw dev shouldnt display output unless there's an error
                    with lock:
                        err = '['+R+'-'+W+'] Channel hopping failed: '+R+line+W+'\n    \
Try disconnecting the monitor mode\'s parent interface (e.g. wlan0)\n    \
from the network if you have not already\n'
                    break
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit()

def target_APs():
    os.system('clear')
    if err:
        print err
    print '['+G+'+'+W+'] Ctrl-C at any time to copy an access point from below'
    print 'num  ch   ESSID'
    print '---------------'
    for ap in APs:
        print G+str(ap).ljust(2)+W+' - '+APs[ap][0].ljust(2)+' - '+T+APs[ap][1]+W

def copy_AP():
    copy = None
    while not copy:
        try:
            copy = raw_input('\n['+G+'+'+W+'] Choose the ['+G+'num'+W+'] of the AP you wish to copy: ')
            copy = int(copy)
        except Exception:
            copy = None
            continue
    channel = APs[copy][0]
    essid = APs[copy][1]
    if str(essid) == "\x00":
        essid = ' '
    mac = APs[copy][2]
    return channel, essid, mac

def targeting_cb(pkt):
    global APs, count
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        try:
            ap_channel = str(ord(pkt[Dot11Elt:3].info))
        except Exception:
            return
        essid = pkt[Dot11Elt].info
        mac = pkt[Dot11].addr2
        if len(APs) > 0:
            for num in APs:
                if essid in APs[num][1]:
                    return
        count += 1
        APs[count] = [ap_channel, essid, mac]
        target_APs()

def iwconfig():
    monitors = []
    interfaces = {}
    proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue # Isn't an empty string
        if line[0] != ' ': # Doesn't start with space
            #ignore_iface = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]|at[0-9]', line)
            #if not ignore_iface: # Isn't wired or at0 tunnel
            iface = line[:line.find(' ')] # is the interface name
            if 'Mode:Monitor' in line:
                monitors.append(iface)
            elif 'IEEE 802.11' in line:
                if "ESSID:\"" in line:
                    interfaces[iface] = 1
                else:
                    interfaces[iface] = 0
    return monitors, interfaces

def rm_mon():
    monitors, interfaces = iwconfig()
    for m in monitors:
        if 'mon' in m:
            Popen(['airmon-ng', 'stop', m], stdout=DN, stderr=DN)
        else:
            Popen(['ifconfig', m, 'down'], stdout=DN, stderr=DN)
            Popen(['iw', 'dev', m, 'mode', 'managed'], stdout=DN, stderr=DN)
            Popen(['ifconfig', m, 'up'], stdout=DN, stderr=DN)



def AP_iface(interfaces, inet_iface):
    for i in interfaces:
        if i != inet_iface:
            return i

def start_monitor(ap_iface, channel):
    proc = Popen(['airmon-ng', 'start', ap_iface, channel], stdout=PIPE, stderr=DN)
    for line in proc.communicate()[0].split('\n'):
        if "monitor mode enabled" in line:
            line = line.split()
            mon_iface = line[4][:-1]
            return mon_iface

def get_mon_mac(mon_iface):
    '''http://stackoverflow.com/questions/159137/getting-mac-address'''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon_iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    return mac

def start_ap(mon_iface, channel, essid, args):
    print '['+T+'*'+W+'] Starting the fake access point...'
    if args.wpa:
        Popen(['airbase-ng', '-P', '-Z', '4', '-W', '1', '-c', channel, '-e', essid, '-v', mon_iface, '-F', 'fakeAPlog'], stdout=DN, stderr=DN)
    else:
        Popen(['airbase-ng', '-c', channel, '-e', essid, '-v', mon_iface], stdout=DN, stderr=DN)
    try:
        time.sleep(6) # Copied from Pwnstar which said it was necessary?
    except KeyboardInterrupt:
        cleanup(None, None)
    Popen(['ifconfig', 'at0', 'up', '10.0.0.1', 'netmask', '255.255.255.0'], stdout=DN, stderr=DN)
    Popen(['ifconfig', 'at0', 'mtu', '1400'], stdout=DN, stderr=DN)

def sniffing(interface, cb):
    sniff(iface=interface, prn=cb, store=0)

def mon_mac(mon_iface):
    '''
    http://stackoverflow.com/questions/159137/getting-mac-address
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon_iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    return mac

def cleanup(signal, frame):
    # with open('/proc/sys/net/ipv4/ip_forward', 'r+') as forward:
    #     forward.write(forw)
    # os.system('iptables -F')
    # os.system('iptables -X')
    # os.system('iptables -t nat -F')
    # os.system('iptables -t nat -X')
    os.system('pkill airbase-ng')
    os.system('pkill dhcpd') # Dangerous?
    rm_mon()
    sys.exit('\n['+G+'+'+W+'] Cleaned up')

if __name__ == '__main__':
    global ipf, mon_iface, ap_mac

    if os.geteuid() != 0:
        sys.exit('['+R+'-'+W+'] Run as root')

    channel = '1'
    if args.channel:
        channel = args.channel
    essid = 'Free Wifi'
    if args.essid:
        essid = args.essid

    monitors, interfaces = iwconfig()
    rm_mon()
    inet_iface, ipprefix = internet_info(interfaces)
    ap_iface = AP_iface(interfaces, inet_iface)
    if not ap_iface:
        sys.exit('['+R+'-'+W+'] Found internet connected interface in '+T+inet_iface+W+'. Please bring up a wireless interface to use as the fake access point.')


    mon_iface = start_monitor(ap_iface, channel)
    mon_mac1 = get_mon_mac(mon_iface)
    if args.targeting:
        hop = Thread(target=channel_hop, args=(mon_iface,))
        hop.daemon = True
        hop.start()
        sniffing(mon_iface, targeting_cb)
        channel, essid, ap_mac = copy_AP()
    start_ap(mon_iface, channel, essid, args)


    raw_input('Press any key..')