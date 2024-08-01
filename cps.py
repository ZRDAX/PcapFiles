from scapy.all import sniff, DNSQR, IP
import psycopg2

def packet_callback(packet):
    if packet.haslayer(DNSQR):  # Verifica se o pacote tem camada DNS
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        query_name = packet[DNSQR].qname.decode('utf-8')

        # Conectar ao PostgreSQL e armazenar os dados
        conn = psycopg2.connect("dbname=yourdb user=youruser password=yourpass")
        cur = conn.cursor()
        cur.execute("INSERT INTO traffic_data (ip_src, ip_dst, query_name) VALUES (%s, %s, %s)",
                    (ip_src, ip_dst, query_name))
        conn.commit()
        cur.close()
        conn.close()

# Captura pacotes na interface de rede 'eth0'
sniff(filter="udp port 53", prn=packet_callback, store=0, iface='eth0')
