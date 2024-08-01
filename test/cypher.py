from scapy.all import *
import socket

# Obter o IP do gateway
gateway_ip = "192.168.1.1"  # substitua pelo IP do seu gateway

# Definir o intervalo de IPs para varredura
ip_range = "192.168.1.0/24"

# Lista para armazenar informações dos dispositivos
devices = []

# Função para obter o hostname a partir do IP
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

# Realizar varredura ARP
arp_req = ARP(pdst=ip_range)
broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
arp_req_broadcast = broadcast/arp_req
answered_list = srp(arp_req_broadcast, timeout=2, verbose=False)[0]

for element in answered_list:
    device = {
        "ip": element[1].psrc,
        "mac": element[1].hwsrc,
        "hostname": get_hostname(element[1].psrc),
        "fqdn": None  # Placeholder para o FQDN
    }
    devices.append(device)

# Função para processar pacotes DNS
def process_dns(packet):
    if packet.haslayer(DNSRR):
        ip = packet[IP].src
        for device in devices:
            if device["ip"] == ip:
                device["fqdn"] = packet[DNSRR].rrname.decode("utf-8")

# Capturar pacotes DNS
sniff(filter="udp port 53", prn=process_dns, timeout=10)

# Exibir os dispositivos capturados
for device in devices:
    print(f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}, FQDN: {device['fqdn']}")
