#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from threading import Thread
from time import sleep
from scapy.all import *
import logging

if LINUX:
    try:
        import PyLorcon2
    except ImportError:
        print("Please install PyLorcon2")
        exit(-1)



class Hopper(Thread):
    """
    Control a card and cause it to hop channels
    Only one card per instance
    """
    def __init__(self, interface, wait=4):
        """
        set the channel hopping sequence
        """
        Thread.__init__(self)
        Thread.daemon = True

        self.wait = wait
        if LINUX:
            self.iface = PyLorcon2.Context(interface)
            self.iface.open_injmon()
        elif DARWIN:
            self.iface = interface
        else:
            raise NotImplemented
        self.HOPpause = False
        # dwell for 3 time slices on 1 6 11
        # default is 3/10 of a second
        # got the lists from kismet config file
        # thanks dragorn!
        self.channellist = [1, 6, 11, 14, 2, 7, 3, 8, 4, 9, 5, 10,
        36, 38, 40, 42, 44, 46, 52, 56, 58, 60, 100, 104, 108, 112,
        116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
        self.hopList = []
        self.current = 0
        self.check_channels()

    def check_channels(self):
        """
        card drivesr suck, determine what channels
        a card supports before we start hopping
        """
        # try setting 802.11ab channels first
        # this may not work depending on 5ghz dfs
        # reverse so we start with 5ghz channels first
        logging.debug('Gettings available channels...')
        for ch in self.channellist:
            if self.set_channel(ch, check=False):
                self.hopList.append(ch)
        logging.debug('Available channels for hopping:')
        logging.debug(self.hopList)

    def pause(self):
        """
        Pause the channel hopping
        """
        self.HOPpause = True

    def unpause(self):
        """
        Unpause the channel hopping
        """
        self.HOPpause = False

    def set_channel(self, channel, check=True):
        logging.debug('[*] Switching channel to %s' % channel)
        print('[*] Switching channel to %s' % channel)

        if check and channel not in self.hopList:
            logging.error('[!] Channel %s not inhop list' % channel)
            return False

        if LINUX:
            return self.linux_set_channel(channel)
        elif DARWIN:
            return self.osx_set_channel(channel)
        else:
            raise NotImplemented

    def osx_set_channel(self, channel):
        from subprocess import Popen, PIPE
        cmd = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        Popen('%s -c%s' % (cmd, channel), shell=True).wait()
        # out, err = Popen([cmd, '-c%s'%channel], stdout=PIPE, stderr=PIPE).communicate()
        # print(out)
        # if err is not None and err.find("Error configuring channel.") != -1:
        #     return False
        return True

    def linux_set_channel(self, channel):
        try:
            self.iface.set_channel(channel)
            return True
        except PyLorcon2.Lorcon2Exception:
            return False


    def run(self):
        """
        Hop channels
        """
        while True:
            for ch in self.hopList:
                # hopping is paused though loop still runs
                if self.HOPpause is True:
                    continue

                if not self.set_channel(ch):
                    continue

                self.current = ch

                if ch in [1, 6, 11]:
                    # dwell for 4/10 of a second
                    # we want to sit on 1 6 and 11 a bit longer
                    sleep(.5)
                else:
                    sleep(.3)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    Hopper('en1',).start()
    raw_input('Press enter to stop...')