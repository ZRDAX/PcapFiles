import pyshark

def extract_ips(packet):
    ip_addresses = []
    if 'IP' in packet:
        if 'src' in packet.ip.field_names:
            ip_addresses.append(packet.ip.src)
        if 'dst' in packet.ip.field_names:
            ip_addresses.append(packet.ip.dst)
    return ip_addresses

def extract_macs(packet):
    mac_addresses = []
    if 'eth' in packet:
        if 'src' in packet.eth.field_names:
            mac_addresses.append(packet.eth.src)
        if 'dst' in packet.eth.field_names:
            mac_addresses.append(packet.eth.dst)
    return mac_addresses

def extract_hostnames(packet):
    hostnames = []
    if 'DNS' in packet:
        if 'qry_name' in packet.dns.field_names:
            hostnames.append(packet.dns.qry_name)
        if 'resp_name' in packet.dns.field_names:
            hostnames.append(packet.dns.resp_name)
    return hostnames

# Ler o arquivo de captura pcap
cap = pyshark.FileCapture('captura.pcap')

ips = set()
macs = set()
hostnames = set()

for packet in cap:
    ips.update(extract_ips(packet))
    macs.update(extract_macs(packet))
    hostnames.update(extract_hostnames(packet))

# Exibição das informações extraídas
print("Endereços IP:")
for ip in ips:
    print(ip)

print("\nEndereços MAC:")
for mac in macs:
    print(mac)

print("\nHostnames e FQDNs:")
for hostname in hostnames:
    print(hostname)
