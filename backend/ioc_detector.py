import re

def detect_iocs(file_bytes):
    """
    Simulates IoC extraction by looking for common patterns in strings.
    In a real scenario, this would use 'strings' command equivalent and 
    parse PE headers for imports, network artifacts, etc.
    """
    iocs = []
    try:
        content_str = file_bytes.decode('utf-8', errors='ignore')
    except Exception:
        content_str = str(file_bytes)
        
    # Simple regex for IPs
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, content_str)
    for ip in set(ips):
        # Ignore some common local IPs for realism
        if not ip.startswith('127.') and not ip.startswith('0.'):
            iocs.append({"type": "ip", "value": ip})
            
    # Simple regex for URLs
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    urls = re.findall(url_pattern, content_str)
    for url in set(urls):
        iocs.append({"type": "url", "value": url})
        
    # Simulated IoCs for demonstration if it's an executable or small file
    if b'MZ' in file_bytes[:2]:
        # Fake IoC injection for demo purposes on EXEs
        iocs.append({"type": "url", "value": "http://malicious-c2-server.evil/drop.exe"})
        iocs.append({"type": "ip", "value": "192.168.100.44"})
        
    return iocs
