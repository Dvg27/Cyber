import hashlib

def calculate_hashes(file_bytes):
    """Calculates MD5 and SHA-256 for the given file bytes."""
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    
    return {
        "md5": md5_hash,
        "sha256": sha256_hash
    }
