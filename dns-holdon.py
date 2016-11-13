# python dns-holdon.py -s 130.245.145.6 -n falun.com -t 15
#answers, nonanswers = sr(IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname='falun.com')), verbose=0, timeout=15, multi=True)
import argparse
from scapy.all import *
import pdb
import time
import math

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--server-ip", default="130.245.145.6", dest="server", help="IP of DNS server", required=True)
parser.add_argument("-n", "--hostname", default="falun.com", dest="hostname", help="The URL that you wish to perform a DNS lookup for", required=True)
parser.add_argument("-t", "--timeout", default=5, dest="timeout", help="The amount of time (in seconds) to wait for a real response", type=float, required=True)
args = parser.parse_args()

# First, send a non-sensitive query to a safe DNS resolver and pull the RTT and TTL for later
non_sensitive_send_time = time.time()
answer = sr1(IP(dst='130.245.145.6')/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname='m.pvta.com')), verbose=0)
non_sensitive_recv_time = answer.time
non_sensitive_rtt = non_sensitive_recv_time - non_sensitive_send_time
non_sensitive_ttl = answer[IP].ttl


sensitive_send_time = time.time()
answers, nonanswers = sr(IP(dst=args.server)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=args.hostname)), verbose=0, timeout=args.timeout, multi=True)
for answer in answers:
    sensitive_recv_time = answer[-1].time
    sensitive_rtt = sensitive_recv_time - sensitive_send_time
    rtt_difference = math.fabs(sensitive_rtt - non_sensitive_rtt)
    print rtt_difference
    if answer[-1][IP].ttl != non_sensitive_ttl and sensitive_rtt <= non_sensitive_rtt/2:
        print 'injection!'
    # answer is a tuple.  Last entry in the tuple contains
    # the dns record, which contains the actual response.
    else:
        pdb.set_trace()
        print answer[-1][DNSRR].rdata
#print answer.IP
#print answered[DNS][1]
