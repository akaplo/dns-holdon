import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--server-ip", default="8.8.8.8", dest="server", help="IP of DNS server", required=True)
parser.add_argument("-n", "--hostname", default="m.pvta.com", dest="hostname", help="The URL that you wish to perform a DNS lookup for", required=True)
args = parser.parse_args()
