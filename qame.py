import re

# Exemplo de análise de um arquivo de captura
with open('domestic.pcap', 'r') as file:
    data = file.read()

# Procurar por endereços IP específicos
ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', data)

# Procurar por URLs
urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', data)

print("Endereços IP encontrados:", ips)
print("URLs encontradas:", urls)
