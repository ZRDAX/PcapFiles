import logging
import time
from scapy.all import sniff, IP, Ether, DNS, DNSQR
from threading import Thread

# Configurar o logging
logging.basicConfig(filename='network_logs.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

packet_log = []  # Lista para armazenar os logs temporários

def packet_handler(packet):
    log_entry = []

    # Verificar se o pacote tem uma camada Ethernet
    if Ether in packet:
        ether_layer = packet[Ether]
        mac_src = ether_layer.src
        mac_dst = ether_layer.dst
        log_entry.append(f"MACo: {mac_src}, MACd: {mac_dst}")

    # Verificar se o pacote tem uma camada IP
    if IP in packet:
        ip_layer = packet[IP]
        ip_src = ip_layer.src
        ip_dst = ip_layer.dst
        log_entry.append(f"IPo: {ip_src}, IPd: {ip_dst}")

    # Verificar se o pacote tem uma camada DNS
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        dns_layer = packet[DNSQR]
        fqdn = dns_layer.qname.decode('utf-8')
        log_entry.append(f"FQDN: {fqdn}")

    if log_entry:
        logging.info(", ".join(log_entry))
        packet_log.append(", ".join(log_entry))

def print_logs_periodically():
    while True:
        if packet_log:
            for entry in packet_log:
                print(entry)
            packet_log.clear()  # Limpar a lista após imprimir
        time.sleep(5)

# Iniciar a captura de pacotes em um thread separado
sniff_thread = Thread(target=lambda: sniff(prn=packet_handler, store=0, iface='eth0', promisc=True))
sniff_thread.start()

# Iniciar o loop de impressão periódica
print_logs_periodically()
