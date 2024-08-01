import subprocess
import time

def capture_packets():
    capture_command = [
        'tshark', '-i', 'eth0', '-T', 'fields',
        '-e', 'ip.src', '-e', 'ip.dst',
        '-e', 'dns.qry.name', '-e', 'dns.resp.name',
        '-w', '/path/to/output.pcap'
    ]
    subprocess.run(capture_command)

while True:
    capture_packets()
    time.sleep(300)  # Capture a cada 5 minutos
