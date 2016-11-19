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
non_sensitive_rtt = answer.time - non_sensitive_send_time
non_sensitive_ttl = answer[IP].ttl

answers, nonanswers = sr(IP(dst=args.server)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=args.hostname)), verbose=0, timeout=args.timeout, multi=True)
for answer in answers:
    sensitive_send_time = answer[0].sent_time
    sensitive_recv_time = answer[-1].time
    sensitive_rtt = sensitive_recv_time - sensitive_send_time
    # print 'sensitive'
    # print sensitive_rtt
    # print 'half non sensitive'
    # print non_sensitive_rtt / 2
    rtt_difference = math.fabs(sensitive_rtt - non_sensitive_rtt)
    # This line should actually be
    # > if answer[-1][IP].ttl != non_sensitive_ttl and sensitive_rtt <= non_sensitive_rtt/2
    # however, our testing server sends all responses with the same TTL.
    print sensitive_rtt
    print non_sensitive_rtt/2
    print answer[-1][DNS].summary()
    if sensitive_rtt < non_sensitive_rtt/2:
        print 'An evil DNS resolver tried to lie and tell you that ' + args.hostname + ' is at ' + answer[-1][DNSRR].rdata + ' but it\'s not!'
    # answer is a tuple.  Last entry in the tuple contains
    # the dns record, which contains the actual response.
    else:
        print args.hostname + ' is actually at ' + answer[-1][DNSRR].rdata
#print answer.IP
#print answered[DNS][1]
