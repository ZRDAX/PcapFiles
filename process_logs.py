import re

# Definir expressões regulares para extrair informações
regex_mac = re.compile(r'MACo: ([0-9A-Fa-f:]{17}), MACd: ([0-9A-Fa-f:]{17})')
regex_ip = re.compile(r'IPo: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}), IPd: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
regex_fqdn = re.compile(r'FQDN: ([^\s,]+)')
regex_intrusion = re.compile(r'Intrusion: ([^,]+)')

# Conjuntos para armazenar entradas únicas
unique_mac = set()
unique_ip = set()
unique_fqdn = set()
unique_intrusion = set()

# Função para processar o arquivo de log
def process_logs(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    
    for line in logs:
        mac_match = regex_mac.search(line)
        ip_match = regex_ip.search(line)
        fqdn_match = regex_fqdn.search(line)
        intrusion_match = regex_intrusion.search(line)

        if mac_match:
            mac_src, mac_dst = mac_match.groups()
            mac_entry = (mac_src, mac_dst)
            if mac_entry not in unique_mac:
                unique_mac.add(mac_entry)
                print(f"MAC Source: {mac_src}, MAC Destination: {mac_dst}")

        if ip_match:
            ip_src, ip_dst = ip_match.groups()
            ip_entry = (ip_src, ip_dst)
            if ip_entry not in unique_ip:
                unique_ip.add(ip_entry)
                print(f"IP Source: {ip_src}, IP Destination: {ip_dst}")

        if fqdn_match:
            fqdn = fqdn_match.group(1)
            if fqdn not in unique_fqdn:
                unique_fqdn.add(fqdn)
                print(f"FQDN: {fqdn}")

        if intrusion_match:
            intrusion = intrusion_match.group(1)
            if intrusion not in unique_intrusion:
                unique_intrusion.add(intrusion)
                print(f"Intrusion Detected: {intrusion}")

# Caminho para o arquivo de log
log_file_path = 'LogsGET.txt'

# Processar os logs
process_logs(log_file_path)
