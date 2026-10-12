import re

IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
BTC_PATTERN = re.compile(r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,45})\b')
ETH_PATTERN = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
ONION_PATTERN = re.compile(r'\b[a-z2-7]{16,56}\.onion\b', re.IGNORECASE)
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
REGISTRY_PATTERN = re.compile(r'(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[A-Za-z0-9_\\]+', re.IGNORECASE)

def detect_iocs(file_bytes):
    """
    Extracts Indicators of Compromise (IoCs) including network artifacts,
    crypto ransom payment addresses, and persistence points.
    """
    iocs = []
    content_str = file_bytes.decode('utf-8', errors='ignore')

    # IPv4 detection
    ips = IP_PATTERN.findall(content_str)
    for ip in set(ips):
        try:
            octets = [int(octet) for octet in ip.split('.')]
            if all(octet <= 255 for octet in octets) and not ip.startswith(('127.', '0.', '255.')):
                iocs.append({"type": "ip", "value": ip})
        except ValueError:
            pass

    # URL detection
    urls = URL_PATTERN.findall(content_str)
    for url in set(urls):
        cleaned_url = url.rstrip('.,;:\'")')
        if len(cleaned_url) > 10:
            iocs.append({"type": "url", "value": cleaned_url})

    # Dark web / Onion domains
    onions = ONION_PATTERN.findall(content_str)
    for onion in set(onions):
        iocs.append({"type": "c2_domain", "value": onion})

    # Bitcoin / Crypto addresses (often associated with ransomware/blackmail)
    btc_matches = BTC_PATTERN.findall(content_str)
    for btc in set(btc_matches):
        iocs.append({"type": "crypto_address", "value": f"BTC: {btc}"})

    eth_matches = ETH_PATTERN.findall(content_str)
    for eth in set(eth_matches):
        iocs.append({"type": "crypto_address", "value": f"ETH: {eth}"})

    # Emails
    emails = EMAIL_PATTERN.findall(content_str)
    for email in set(emails):
        # Exclude typical file format false positives
        if not email.endswith(('.png', '.jpg', '.pdf', '.exe', '.dll')):
            iocs.append({"type": "email", "value": email})

    # Suspicious registry persistence paths
    regs = REGISTRY_PATTERN.findall(content_str)
    for reg in set(regs):
        iocs.append({"type": "registry", "value": reg})

    return iocs

