# chinese IPS: route server 'I' at 192.36.148.17:
# python dns-holdon.py -s 192.36.148.17 -n m.pvta.com -t 15
# WARNING: No route found for IPv6 destination :: (no default route?)
# 0.0929789543152
# 0.0370810031891
# DNS Ans
# m.pvta.com is actually at i.gtld-servers.net.

#https://www.ultratools.com/tools/asnInfoResult?domainName=222.73.128.165

# python dns-holdon.py -s 130.245.145.6 -n falun.com -t 15
#answers, nonanswers = sr(IP(dst='8.8.8.8')/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname='falun.com')), verbose=0, timeout=15, multi=True)
import argparse
from scapy.all import *
import time

# Prepare the 3 required params
parser = argparse.ArgumentParser()
parser.add_argument("-s", "--server-ip", default="130.245.145.6", dest="server", help="IP of DNS server", required=True)
parser.add_argument("-n", "--hostname", default="falun.com", dest="hostname", help="The URL that you wish to perform a DNS lookup for", required=True)
parser.add_argument("-t", "--timeout", default=15, dest="timeout", help="The amount of time (in seconds) to wait for a real response", type=float, required=True)
args = parser.parse_args()

# First, send a non-sensitive query to a safe DNS resolver and pull the RTT and TTL for later
# Timestamp for when we sent the query; used for calculating RTT
non_sensitive_send_time = time.time()
answer = sr1(IP(dst='130.245.145.6')/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname='m.pvta.com')), verbose=0)
# The RTT of the non-sensitive query
non_sensitive_rtt = answer.time - non_sensitive_send_time
# The TTL of the non-sensitive query
non_sensitive_ttl = answer[IP].ttl

# Construct a DNS query, send it, and wait a configurable amount of time for
# a response.
answers, nonanswers = sr(IP(dst=args.server)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=args.hostname)), verbose=0, timeout=args.timeout, multi=True)
# We only care about the answers to our query.  Let's look at each one:
for answer in answers:
    # Determine the RTT for the entire send/receive of this packet.
    sensitive_send_time = answer[0].sent_time
    sensitive_recv_time = answer[-1].time
    sensitive_rtt = sensitive_recv_time - sensitive_send_time
    # DNS Hold-On specifies that a response received in
    # less than half of the expected time was injected.
    # This line should actually be
    # > if answer[-1][IP].ttl != non_sensitive_ttl and sensitive_rtt < non_sensitive_rtt/2
    # however, our testing server sends all responses with the same TTL.
    if sensitive_rtt < non_sensitive_rtt/2:
        print 'An evil DNS resolver tried to lie and tell you that ' + args.hostname + ' is at ' + answer[-1][DNSRR].rdata + ' but it\'s not!'
    # Otherwise, we can say the response was a legitimate.
    else:
        # answer is a tuple.  Last entry in the tuple contains
        # the dns record, which contains the actual response.
        print args.hostname + ' is actually at ' + answer[-1][DNSRR].rdata
#print answer.IP
#print answered[DNS][1]
