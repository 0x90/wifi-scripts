#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Switch 802.11 interface(s) to INJMON mode.
# author: @090h
#

from sys import argv, exit
import logging

try:
    from PyLorcon2 import Context, auto_driver
except ImportError:
    logging.error('PyLorcon2 not installed!')
    exit(-1)

try:
    # import scapy silently
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import get_if_list, conf
    conf.verb = 0
except ImportError:
    logging.error('Scapy not installed!')
    exit(-1)


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