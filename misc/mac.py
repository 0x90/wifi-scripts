#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from oui import OUI
import re
from random import randint


class MAC(object):
    def __init__(self, address):
        self.address = address
        if not MAC.is_valid(address):
            raise Exception("Invalid MAC Address")
        self.mac = address.replace(':', '').replace('-', '')

    @staticmethod
    def is_valid(address):
        "Return True if it is a valid mac address."
        macAddress = re.compile("^((?:[0-9a-fA-F]{2}[:]){5}[0-9a-fA-F]{2})$")
        return True if macAddress.match(address) else False

    @staticmethod
    def random():
        mac = [0x00, 0x16, 0x3e,
               randint(0x00, 0x7f),
               randint(0x00, 0xff),
               randint(0x00, 0xff)]
        return ':'.join(map(lambda x: "%02x" % x, mac))

    #
    @property
    def nic(self):
        '''
        Parses out the NIC portion of an ASCII MAC address.

        @mac_address - An ASCII string MAC address or NIC,
                       with or without delimiters.

        Returns the NIC portion of the MAC address as an int.
        '''
        # mac = self.mac.replace(':', '').replace('-', '')
        mac = self.mac
        if len(mac) == 12:
            try:
                nic = int(mac[6:], 16)
            except ValueError as e:
                raise Exception("Invalid NIC: [%s]" % mac[6:])
        elif len(mac) == 6:
            try:
                nic = int(mac, 16)
            except ValueError as e:
                raise Exception("Invalid NIC: [%s]" % mac)
        else:
            raise Exception("Invalid MAC address: [%s]" % mac)

        return nic

    @property
    def vendor(self):
        return OUI().get_vendor(self.address)