import socket
import dns.resolver
from scapy.all import sniff, Ether, IP

devices = {}

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def resolve_fqdn(ip):
    try:
        result = dns.resolver.resolve_address(ip)
        return result[0].to_text()
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return None

def packet_callback(packet):
    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst

        if src_mac not in devices:
            devices[src_mac] = {"ip": None, "hostname": None, "fqdn": None}
        
        if dst_mac not in devices:
            devices[dst_mac] = {"ip": None, "hostname": None, "fqdn": None}

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if devices[src_mac]["ip"] is None:
                devices[src_mac]["ip"] = src_ip
                devices[src_mac]["hostname"] = resolve_hostname(src_ip)
                devices[src_mac]["fqdn"] = resolve_fqdn(src_ip)
                
            if devices[dst_mac]["ip"] is None:
                devices[dst_mac]["ip"] = dst_ip
                devices[dst_mac]["hostname"] = resolve_hostname(dst_ip)
                devices[dst_mac]["fqdn"] = resolve_fqdn(dst_ip)

sniff(prn=packet_callback, store=0)
