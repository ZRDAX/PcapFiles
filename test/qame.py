from elasticsearch import Elasticsearch
import pyshark
import re

es = Elasticsearch(['http://localhost:9200'])

cap = pyshark.FileCapture('qame.py')
for packet in cap:
    packet_str = str(packet)
    
    # Extrair informações relevantes usando RegEx
    ip = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', packet_str)
    url = re.search(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', packet_str)
    
    if ip or url:
        document = {
            'ip': ip.group(0) if ip else None,
            'url': url.group(0) if url else None,
            'raw': packet_str
        }
        es.index(index='network_traffic', body=document)
