#!/usr/bin/env python2
#############################################################################
##                                                                         ##
## eapy.py --- Simplistic 802.1X authentication client                     ##
##                                                                         ##
## Copyright (C) 2002  Philippe Biondi <biondi@cartel-securite.fr>         ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License as published by the   ##
## Free Software Foundation; either version 2, or (at your option) any     ##
## later version.                                                          ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################


from socket import *
from struct import *
from md5 import md5


###  Authentication parameters

USER = "test"
PASS = "toto"
DEV = "eth1"


### Constants

ETHERTYPE_PAE = 0x888e
PAE_GROUP_ADDR = "\x01\x80\xc2\x00\x00\x03"

EAPOL_VERSION = 1
EAPOL_EAPPACKET = 0
EAPOL_START = 1
EAPOL_LOGOFF = 2
EAPOL_KEY = 3
EAPOL_ASF = 4

EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4

EAP_TYPE_ID = 1
EAP_TYPE_MD5 = 4


### Packet builders

def EAPOL(type, payload=""):
    return pack("!BBH", EAPOL_VERSION, type, len(payload))+payload

def EAP(code, id, type=0, data=""):
    if code in [EAP_SUCCESS, EAP_FAILURE]:
        return pack("!BBH", code, id, 4)
    else:
        return pack("!BBHB", code, id, 5+len(data), type)+data

def ethernet_header(src, dst, type):
    return dst+src+pack("!H",type)


### Main program

s=socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_PAE))
s.bind((DEV, ETHERTYPE_PAE))

mymac=s.getsockname()[4]
llhead=ethernet_header(mymac, PAE_GROUP_ADDR, ETHERTYPE_PAE)


print "--> Sent EAPOL Start"
s.send(llhead+EAPOL(EAPOL_START))

try:
    while 1:
        p = s.recv(1600)[14:]
        vers,type,eapollen  = unpack("!BBH",p[:4])
        if type == EAPOL_EAPPACKET:
            code, id, eaplen = unpack("!BBH", p[4:8])
            if code == EAP_SUCCESS:
                print "Got EAP Success"
            elif code == EAP_FAILURE:
                print "Got EAP Failure"
            elif code == EAP_RESPONSE:
                print "?? Got EAP Response"
            elif code == EAP_REQUEST:
                reqtype = unpack("!B", p[8:9])[0]
                reqdata = p[9:4+eaplen]
                if reqtype == EAP_TYPE_ID:
                    print "Got EAP Request for identity"
                    s.send(llhead+
                           EAPOL(EAPOL_EAPPACKET,
                                 EAP(EAP_RESPONSE,
                                     id,
                                     reqtype,
                                     USER)))
                    print "--> Sent EAP response with identity = [%s]" % USER
                elif reqtype == EAP_TYPE_MD5:
                    print "Got EAP Request for MD5 challenge"
                    challenge=pack("!B",id)+PASS+reqdata[1:]
                    resp=md5(challenge).digest()
                    resp=chr(len(resp))+resp
                    s.send(llhead+
                           EAPOL(EAPOL_EAPPACKET,
                                 EAP(EAP_RESPONSE,
                                     id,
                                     reqtype,
                                     resp)))
                    print "--> Send EAP response with MD5 challenge"
                else:
                    print "?? Got unknown Request type (%i)" % reqtype
            else:
                print "?? Got unknown EAP code (%i)" % code
        else:
            print "Got EAPOL type %i" % type
except KeyboardInterrupt:
    print "Interrupted by user"
        
        












