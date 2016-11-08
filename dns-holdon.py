# python dns-holdon.py -s 130.245.145.6 -n falun.com -t 15
import argparse
from scapy.all import *
import pdb

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--server-ip", default="130.245.145.6", dest="server", help="IP of DNS server", required=True)
parser.add_argument("-n", "--hostname", default="falun.com", dest="hostname", help="The URL that you wish to perform a DNS lookup for", required=True)
parser.add_argument("-t", "--timeout", default=5, dest="timeout", help="The amount of time (in seconds) to wait for a real response", type=float, required=True)
args = parser.parse_args()

# First, send a non-sensitive query to a safe DNS resolver and pull the RTT and TTL for later
answer = sr1(IP(dst='130.245.145.6')/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname='m.pvta.com')), verbose=0)
peepee_el = answer[IP].ttl


answers, nonanswers = sr(IP(dst=args.server)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=args.hostname)), verbose=0, timeout=args.timeout, multi=True)
for answer in answers:
    #pdb.set_trace()
    if answer[-1][IP].ttl != peepee_el:
        print 'injection!'
    # answer is a tuple.  Last entry in the tuple contains
    # the dns record, which contains the actual response.
    else:
        print answer[-1][DNSRR].rdata
#print answer.IP
#print answered[DNS][1]
