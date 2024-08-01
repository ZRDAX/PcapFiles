import pyshark
import psycopg2

def process_pcap(file_path):
    cap = pyshark.FileCapture(file_path)
    conn = psycopg2.connect("dbname=yourdb user=youruser password=yourpass")
    cur = conn.cursor()
    
    for packet in cap:
        try:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            qry_name = packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else None
            resp_name = packet.dns.resp_name if hasattr(packet.dns, 'resp_name') else None

            cur.execute("INSERT INTO traffic_data (ip_src, ip_dst, qry_name, resp_name) VALUES (%s, %s, %s, %s)",
                        (ip_src, ip_dst, qry_name, resp_name))
        except AttributeError:
            continue

    conn.commit()
    cur.close()
    conn.close()

process_pcap('/path/to/output.pcap')
