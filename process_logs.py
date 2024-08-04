
import re

# Definir expressões regulares para extrair informações
regex_mac = re.compile(r'MACo: ([0-9A-Fa-f:]{17}), MACd: ([0-9A-Fa-f:]{17})')
regex_ip = re.compile(r'IPo: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}), IPd: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
regex_fqdn = re.compile(r'FQDN: ([^\s,]+)')
regex_intrusion = re.compile(r'Intrusion: ([^,]+)')

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
            print(f"MAC Source: {mac_src}, MAC Destination: {mac_dst}")

        if ip_match:
            ip_src, ip_dst = ip_match.groups()
            print(f"IP Source: {ip_src}, IP Destination: {ip_dst}")

        if fqdn_match:
            fqdn = fqdn_match.group(1)
            print(f"FQDN: {fqdn}")

        if intrusion_match:
            intrusion = intrusion_match.group(1)
            print(f"Intrusion Detected: {intrusion}")

# Caminho para o arquivo de log
log_file_path = 'LogsGET.txt'

# Processar os logs
process_logs(log_file_path)
