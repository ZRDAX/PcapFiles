# Exemplo Completo
# Aqui está um exemplo completo de um script em Python que captura o tráfego da rede e salva em um arquivo pcap:

from scapy.all import sniff, wrpcap

def packet_callback(packet):
    print(packet.summary())

# Captura os pacotes e salva em um arquivo
packets = sniff(iface="eth0", prn=packet_callback, count=100)  # Remova `count` para captura contínua
wrpcap('capture.pcap', packets)