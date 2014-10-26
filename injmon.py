#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from sys import argv
from PyLorcon2 import Context, auto_driver

# import scapy silently
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# from scapy.all import *
from scapy.all import get_if_list, conf
conf.verb = 0



def injmon(iface=None):
    if iface is None:
        for i in get_if_list():
            injmon(i)
    else:
        try:
            driver, description = auto_driver(iface)
        except:
            # print('Could not find driver for %s' % iface)
            return

        if iface.find('mon') != -1:
            print('%s is already in mon mode' % iface)
            return

        ctx = Context(iface)
        print('Enabling injmon on %s %s' % (iface, driver))
        try:
            ctx.open_injmon()
        except:
            print("Failed to set injmon for %s!" % iface)


if __name__ == '__main__':
    if len(argv) == 1:
        injmon()
    else:
        injmon(argv[1])