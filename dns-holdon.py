# python dns-holdon.py -s 8.8.8.8 -n m.pvta.com
import argparse
from scapy.all import *

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--server-ip", default="8.8.8.8", dest="server", help="IP of DNS server", required=True)
parser.add_argument("-n", "--hostname", default="m.pvta.com", dest="hostname", help="The URL that you wish to perform a DNS lookup for", required=True)
args = parser.parse_args()


answer = sr1(IP(dst=args.server)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=args.hostname)),verbose=0)
print answer[DNS].summary()
