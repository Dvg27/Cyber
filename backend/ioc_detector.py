import re

IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)

def detect_iocs(file_bytes):
    """
    Simulates IoC extraction by looking for common patterns in strings.
    In a real scenario, this would use 'strings' command equivalent and 
    parse PE headers for imports, network artifacts, etc.
    """
    iocs = []
    content_str = file_bytes.decode('utf-8', errors='ignore')
        
    # Simple regex for IPs
    ips = IP_PATTERN.findall(content_str)
    for ip in set(ips):
        # Ignore some common local IPs for realism
        octets = [int(octet) for octet in ip.split('.')]
        if all(octet <= 255 for octet in octets) and not ip.startswith(('127.', '0.')):
            iocs.append({"type": "ip", "value": ip})
            
    # Simple regex for URLs
    urls = URL_PATTERN.findall(content_str)
    for url in set(urls):
        iocs.append({"type": "url", "value": url.rstrip('.,;:')})
        
    return iocs
