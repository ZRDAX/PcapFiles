# Aqui está um exemplo completo de um script em Python que captura o tráfego de rede de dispositivos específicos por IP e salva em um arquivo pcap:

from scapy.all import sniff, wrpcap, IP, Ether

# Lista de IPs e MACs permitidos
allowed_ips = ["192.168.1.2", "192.168.1.3", "192.168.1.4"]
allowed_macs = ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]

def packet_callback(packet):
    if packet.haslayer(IP):
        if packet[IP].src in allowed_ips or packet[IP].dst in allowed_ips:
            print(packet.summary())
            return True
    elif packet.haslayer(Ether):
        if packet[Ether].src in allowed_macs or packet[Ether].dst in allowed_macs:
            print(packet.summary())
            return True
    return False

# Captura os pacotes e salva em um arquivo
packets = sniff(iface="eth0", prn=packet_callback, store=1, count=100)  # Remova `count` para captura contínua
wrpcap('capture.pcap', packets)
