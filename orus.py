import re

# Funções para extrair informações específicas usando RegEx
def extract_ips(text):
    ip_pattern = re.compile(r'(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)')
    return ip_pattern.findall(text)

def extract_macs(text):
    mac_pattern = re.compile(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})')
    return mac_pattern.findall(text)

def extract_hostnames(text):
    hostname_pattern = re.compile(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
    return hostname_pattern.findall(text)

# Leitura do arquivo de captura
with open('captura.txt', 'r') as file:
    data = file.read()

# Extração de informações
ips = extract_ips(data)
macs = extract_macs(data)
hostnames = extract_hostnames(data)

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
