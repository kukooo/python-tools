#!/bin/python3
# Servicios y dispositivos conectados a internet
# Si hay servicio web que saque un screenshot del mismo
import os
import socket
import argparse
from shodan import Shodan

parser = argparse.ArgumentParser(description='Search domains info')
parser.add_argument('-f', '--file', help='File with a domain per line', required=True)
parser.add_argument('-H', '--hostnames', help='Shows \'Hostnames\' that finds for an IP', required=False,action="store_true")
parser.add_argument('-d', '--domains', help='Shows \'Domains\' that finds for an IP', required=False,action="store_true")
parser.add_argument('-c', '--cve', help='Shows \'CVEs\' that finds for an IP', required=False,action="store_true")
args = parser.parse_args()

api = Shodan(os.environ['shodanAPI'])

f = open(args.file, 'r')

for dom in f:
    try:
        ipinfo = api.host(socket.gethostbyname(dom.rstrip()))
        print("Domain: {}\n".format(dom.rstrip()))
        print("\tHost: {}".format(ipinfo["ip_str"]))
        print("\tOrganization: {}".format(ipinfo["org"]))
        print("\tOS: {}".format(ipinfo["os"]))
        for item in ipinfo["data"]:
            print("\tPort: {}".format(item["port"]))
            if item["port"] == 80 :
                os.system("gowitness single http://{} >/dev/null 2>&1".format(dom.rstrip()))
            elif item["port"] == 443:
                os.system("gowitness single https://{} >/dev/null 2>&1".format(dom.rstrip()))
            if args.domains:
                print("\t\tDomains: ")
                for domain in item["domains"]:
                    print("\t\t\t{}".format(domain))
            if args.hostnames:
                print("\t\tHostnames: ")
                for hostname in item["hostnames"]:
                    print("\t\t\t{}".format(hostname))
        if args.cve:
            for item in ipinfo['vulns']:
                CVE = item.replace('!','')
                print('\tVulns: {}'.format(item))
                exploits = api.exploits.search(CVE)
                for item in exploits['matches']:
                    if item.get('cve')[0] == CVE:
                        print("\t{}".format(item.get('description')))
        print("\n")
    except :
        continue
