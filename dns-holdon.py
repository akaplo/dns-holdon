# python dns-holdon.py -s 8.8.8.8 -n m.pvta.com
import argparse
from scapy.all import *

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--server-ip", default="8.8.8.8", dest="server", help="IP of DNS server", required=True)
parser.add_argument("-n", "--hostname", default="m.pvta.com", dest="hostname", help="The URL that you wish to perform a DNS lookup for", required=True)
parser.add_argument("-t", "--timeout", default=5, dest="timeout", help="The amount of time (in seconds) to wait for a real response", required=True)
args = parser.parse_args()

# First, send a non-sensitive query to a safe DNS resolver and pull the RTT and TTL for later
answer = sr1(IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname='m.pvta.com')), verbose=0)
ttl = answer[IP].ttl


answer = sr(IP(dst=args.server)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=args.hostname)), verbose=0, timeout=args.timeout, multi=True)
print answer[DNS].summary()
