
# Escanear a rede para obter IPs e MACs
echo "IP, MAC, Hostname, FQDN" > network_devices.csv
for ip in $(nmap -sn 192.168.1.0/24 -oG - | awk '/Up$/{print $2}'); do
    # Obter o endereço MAC
    mac=$(nmap -sP $ip | awk '/MAC Address/{print $3}')
    
    # Obter o hostname
    hostname=$(nmap -sL $ip | grep $ip | awk '{print $5}')
    
    # Obter o FQDN
    fqdn=$(nslookup $ip | grep 'name =' | awk '{print $4}')
    
    # Adicionar ao arquivo CSV
    echo "$ip, $mac, $hostname, $fqdn" >> network_devices.csv
done

echo "Informações salvas em network_devices.csv"
