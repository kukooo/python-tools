#!/usr/bin/env python
import os
import re
import socket
import argparse
from shodan import Shodan

def is_ip(addr: str) -> bool:
    """Check if string is a valid IPv4 address."""
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    if not ip_pattern.match(addr):
        return False
    try:
        socket.inet_aton(addr)  # validate octets
        return True
    except OSError:
        return False


def main():
    parser = argparse.ArgumentParser(description='Search domains info')
    parser.add_argument(
        '-f', '--file',
        type=argparse.FileType('r'),
        help='File with a domain/IP per line',
        required=True
    )
    parser.add_argument(
        '-H', '--hostnames',
        help="Show 'Hostnames' found for an IP",
        action="store_true"
    )
    parser.add_argument(
        '-d', '--domains',
        help="Show 'Domains' found for an IP",
        action="store_true"
    )
    parser.add_argument(
        '-c', '--cve',
        help="Show 'CVEs' found for an IP",
        action="store_true"
    )
    args = parser.parse_args()

    api = Shodan(os.environ['shodanAPI'])

    for line in args.file:
        target = line.strip()
        if not target:
            continue

        # Decide if it's an IP or hostname
        if is_ip(target):
            ip = target
        else:
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                print(f"[!] Could not resolve hostname: {target}")
                continue

        try:
            ipinfo = api.host(ip)
            print(f"Target: {target} ({ip})\n")
            print(f"\tHost: {ipinfo.get('ip_str')}")
            print(f"\tOrganization: {ipinfo.get('org')}")
            print(f"\tOS: {ipinfo.get('os')}")

            for item in ipinfo.get("data", []):
                print(f"\tPort: {item['port']}")
                if item["port"] == 80:
                    os.system(f"gowitness single http://{target} >/dev/null 2>&1")
                elif item["port"] == 443:
                    os.system(f"gowitness single https://{target} >/dev/null 2>&1")

                if args.domains and item.get("domains"):
                    print("\t\tDomains: ")
                    for domain in item["domains"]:
                        print(f"\t\t\t{domain}")

                if args.hostnames and item.get("hostnames"):
                    print("\t\tHostnames: ")
                    for hostname in item["hostnames"]:
                        print(f"\t\t\t{hostname}")

            if args.cve and 'vulns' in ipinfo:
                for vuln in ipinfo['vulns']:
                    CVE = vuln.replace('!', '')
                    print(f'\tVulns: {vuln}')
                    exploits = api.exploits.search(CVE)
                    for match in exploits.get('matches', []):
                        if match.get('cve') and match['cve'][0] == CVE:
                            print(f"\t{match.get('description')}")

            print("\n")
        except Exception as e:
            print(f"[!] Error processing {target} ({ip}): {e}")
            continue


if __name__ == "__main__":
    main()
