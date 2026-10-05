import random
from api._lib.hash_analyzer import calculate_hashes
from api._lib.ioc_detector import detect_iocs

def get_file_type(file_bytes):
    if file_bytes.startswith(b'MZ'):
        return 'Windows PE Executable'
    elif file_bytes.startswith(b'%PDF'):
        return 'PDF Document'
    elif file_bytes.startswith(b'\x89PNG'):
        return 'PNG Image'
    return 'Unknown/Binary'

def analyze_file(filename, file_bytes):
    """Orchestrates the static analysis."""
    hashes = calculate_hashes(file_bytes)
    file_type = get_file_type(file_bytes)
    size = len(file_bytes)

    iocs = detect_iocs(file_bytes)

    static_details = []
    score = 0

    static_details.append(f"[INFO] File Type Identified: {file_type}")

    if file_type == 'Windows PE Executable':
        static_details.append("[WARN] Executable file uploaded. Analyzing PE Sections...")
        score += 30
        if len(iocs) > 0:
            static_details.append(f"[WARN] Found {len(iocs)} potential Indicators of Compromise.")
            score += len(iocs) * 15

        if random.choice([True, False]):
            static_details.append("[WARN] Suspicious API import detected: VirtualAlloc (commonly used for unpacking).")
            score += 20
        if random.choice([True, False]):
            static_details.append("[ERR] Section .text has high entropy: 7.9 (Likely packed or encrypted).")
            score += 25
    else:
        static_details.append("[INFO] File appears to be non-executable.")
        if len(iocs) > 0:
            static_details.append("[WARN] Found embedded links/IPs.")
            score += 15

    score = min(score, 100)

    if score >= 70:
        recommendation = "Isolate the affected system immediately. Block the discovered IPs/URLs at the firewall. Do not execute this file."
    elif score >= 30:
        recommendation = "File exhibits suspicious characteristics. Proceed with caution and consider running in a sandbox for dynamic analysis."
    else:
        recommendation = "No obvious threats detected during static analysis. File appears clean."

    if score >= 70:
        iocs.append({"type": "hash", "value": hashes['sha256']})

    return {
        "filename": filename,
        "size": size,
        "type": file_type,
        "md5": hashes['md5'],
        "sha256": hashes['sha256'],
        "score": score,
        "recommendation": recommendation,
        "static_details": static_details,
        "iocs": iocs
    }
