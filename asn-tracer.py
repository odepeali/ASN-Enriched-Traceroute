import subprocess
import re
import socket

def get_hops(destination):
    result = subprocess.check_output(['traceroute', '-n', destination], text=True)
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.findall(ip_pattern, result)

def get_asn_info(ip):
    try:
        with socket.create_connection(("v4.whois.cymru.com", 43), timeout=5) as s:
            s.sendall(f" -v {ip}\n".encode())
            response = s.recv(4096).decode().splitlines()
        if len(response) < 2:
            return "-", "-", "-"
        parts = [p.strip() for p in response[1].split('|')]
        return parts[0], parts[2], parts[6]  # ASN, Prefix, AS Name
    except:
        return "-", "-", "-"

if __name__ == "__main__":
    target = input("Enter target (domain or IP): ").strip()
    print(f"{'Hop':<4} {'IP Address':<16} {'ASN':<8} {'Prefix':<18} {'AS Name'}")
    print("-" * 70)

    seen_ips = set()
    for count, ip in enumerate(get_hops(target), 1):
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        asn, prefix, as_name = get_asn_info(ip)
        print(f"{count:<4} {ip:<16} {asn:<8} {prefix:<18} {as_name}")
