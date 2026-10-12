import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from api._lib.hash_analyzer import calculate_hashes
from api._lib.ioc_detector import detect_iocs

EICAR_PATTERN = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

HEURISTIC_RULES = [
    # --- RANSOMWARE ---
    {
        "category": "Ransomware",
        "family": "Ransomware.Generic.Cryptor",
        "rule_id": "RANSOM_SHADOW_DELETE",
        "name": "Volume Shadow Copy Deletion",
        "desc": "Executes commands to destroy Windows backup snapshots and shadow copies (vssadmin/wmic/bcdedit)",
        "patterns": [b'vssadmin delete shadows', b'wmic shadowcopy delete', b'bcdedit /set {default} bootstatuspolicy ignoreallfailures', b'vssadmin.exe delete shadows /all /quiet'],
        "weight": 40,
        "severity": "CRITICAL"
    },
    {
        "category": "Ransomware",
        "family": "Ransomware.Generic.LockNote",
        "rule_id": "RANSOM_NOTE_PHRASES",
        "name": "Ransom Demand / Extortion Note",
        "desc": "Contains extortion phrases demanding cryptocurrency to decrypt user files",
        "patterns": [b'all your files have been encrypted', b'readme_decrypt', b'how_to_restore_files', b'decrypt_files', b'send bitcoin to', b'send monero to', b'pay ransom', b'private key will be destroyed', b'personal decryption code'],
        "weight": 35,
        "severity": "CRITICAL"
    },
    {
        "category": "Ransomware",
        "family": "Ransomware.Generic.Cryptor",
        "rule_id": "RANSOM_CRYPTO_APIS",
        "name": "Cryptographic Encryption APIs",
        "desc": "Imports or references symmetric/asymmetric encryption APIs commonly used by cryptolockers",
        "patterns": [b'CryptEncrypt', b'CryptGenKey', b'BCryptEncrypt', b'CryptAcquireContext', b'AES_encrypt', b'Rijndael'],
        "weight": 20,
        "severity": "HIGH"
    },
    {
        "category": "Ransomware",
        "family": "Ransomware.Generic.ExtMarker",
        "rule_id": "RANSOM_EXTENSIONS",
        "name": "Ransomware Extension Signatures",
        "desc": "References known encrypted file extensions (.locked, .crypted, .lockbit)",
        "patterns": [b'.locked', b'.crypto', b'.crypted', b'.lockbit', b'.wanacry'],
        "weight": 20,
        "severity": "HIGH"
    },

    # --- SPYWARE / INFOSTEALER ---
    {
        "category": "Spyware / InfoStealer",
        "family": "Spyware.Stealer.RedLineHeuristics",
        "rule_id": "STEALER_BROWSER_DATA",
        "name": "Browser Credential Store Targeting",
        "desc": "Targets stored Chromium / Firefox passwords, cookie databases, and autofill vaults",
        "patterns": [b'Login Data', b'Web Data', b'cookies.sqlite', b'places.sqlite', b'key4.db', b'logins.json', b'Google\\Chrome\\User Data'],
        "weight": 35,
        "severity": "CRITICAL"
    },
    {
        "category": "Spyware / InfoStealer",
        "family": "Spyware.Stealer.Generic",
        "rule_id": "STEALER_DPAPI_ACCESS",
        "name": "DPAPI & Windows Vault Decryption",
        "desc": "Calls CryptUnprotectData or VaultCli to extract locally saved secrets and hashes",
        "patterns": [b'CryptUnprotectData', b'VaultCli.dll', b'CredEnumerate', b'SamIConnect', b'lsass.exe', b'VaultGetItem'],
        "weight": 35,
        "severity": "CRITICAL"
    },
    {
        "category": "Spyware / InfoStealer",
        "family": "Spyware.Stealer.WalletHunter",
        "rule_id": "STEALER_CRYPTO_WALLETS",
        "name": "Cryptocurrency Wallet Targeting",
        "desc": "Searches for offline crypto wallet files and browser extensions",
        "patterns": [b'wallet.dat', b'exodus.wallet', b'atomic', b'metamask', b'solana', b'phantom.app'],
        "weight": 25,
        "severity": "HIGH"
    },
    {
        "category": "Spyware / InfoStealer",
        "family": "Spyware.Stealer.Exfiltration",
        "rule_id": "STEALER_TOKEN_EXFIL",
        "name": "Session Token & Chat Exfiltration",
        "desc": "Extracts Discord tokens or uses Telegram Bot API for automated data exfiltration",
        "patterns": [b'DiscordTokens', b'discord/Local Storage', b'api.telegram.org/bot', b'tdata'],
        "weight": 25,
        "severity": "HIGH"
    },

    # --- KEYLOGGER ---
    {
        "category": "Keylogger",
        "family": "Spyware.Keylogger.Generic",
        "rule_id": "KEYLOGGER_HOOK_APIS",
        "name": "Low-Level Keyboard Hook APIs",
        "desc": "Sets global Windows keyboard hooks to intercept keystrokes in background",
        "patterns": [b'SetWindowsHookEx', b'WH_KEYBOARD_LL', b'WH_KEYBOARD', b'RegisterHotKey', b'CallNextHookEx'],
        "weight": 35,
        "severity": "HIGH"
    },
    {
        "category": "Keylogger",
        "family": "Spyware.Keylogger.Poller",
        "rule_id": "KEYLOGGER_ASYNC_KEY",
        "name": "Asynchronous Key State Polling",
        "desc": "Polls key states continuously via GetAsyncKeyState API to capture input",
        "patterns": [b'GetAsyncKeyState', b'GetKeyState', b'GetKeyboardState'],
        "weight": 30,
        "severity": "HIGH"
    },
    {
        "category": "Keylogger",
        "family": "Spyware.Keylogger.LogArtifacts",
        "rule_id": "KEYLOGGER_LOG_MARKERS",
        "name": "Keystroke Logging Buffers",
        "desc": "Contains standard keylogging format strings and keystroke log filenames",
        "patterns": [b'[CAPSLOCK]', b'[BACKSPACE]', b'[ENTER]', b'keystrokes.log', b'keylog.txt'],
        "weight": 25,
        "severity": "HIGH"
    },

    # --- TROJAN / DROPPER / BACKDOOR ---
    {
        "category": "Trojan / Dropper",
        "family": "Trojan.Generic.ProcessInjector",
        "rule_id": "TROJAN_PROCESS_INJECTION",
        "name": "Memory & Process Injection APIs",
        "desc": "Injects malicious code into external running system processes (VirtualAllocEx, WriteProcessMemory)",
        "patterns": [b'VirtualAllocEx', b'WriteProcessMemory', b'CreateRemoteThread', b'QueueUserAPC', b'NtCreateThreadEx', b'VirtualAlloc'],
        "weight": 35,
        "severity": "CRITICAL"
    },
    {
        "category": "Trojan / Dropper",
        "family": "Trojan.Downloader.PayloadPuller",
        "rule_id": "TROJAN_REMOTE_DROPPER",
        "name": "Remote Binary Downloader / Dropper",
        "desc": "Downloads and executes second-stage payloads via bitsadmin, certutil, or URLDownloadToFile",
        "patterns": [b'URLDownloadToFile', b'WinHttpOpen', b'InternetReadFile', b'bitsadmin /transfer', b'certutil -urlcache', b'Invoke-WebRequest -OutFile'],
        "weight": 30,
        "severity": "HIGH"
    },
    {
        "category": "Trojan / Dropper",
        "family": "Trojan.Backdoor.ReverseShell",
        "rule_id": "TROJAN_SHELL_EXEC",
        "name": "Reverse Shell & Hidden Process Spawning",
        "desc": "Launches hidden interactive command interpreters or encoded scripts",
        "patterns": [b'powershell -enc', b'powershell.exe -nop -w hidden', b'cmd.exe /c', b'nc -e', b'bash -i >& /dev/tcp'],
        "weight": 30,
        "severity": "HIGH"
    },
    {
        "category": "Trojan / Dropper",
        "family": "Trojan.Persistence.RegistryRun",
        "rule_id": "TROJAN_PERSISTENCE",
        "name": "Startup Registry Persistence",
        "desc": "Configures automatic execution on system boot via Run keys or Scheduled Tasks",
        "patterns": [b'CurrentVersion\\Run', b'CurrentVersion\\RunOnce', b'schtasks /create'],
        "weight": 20,
        "severity": "MEDIUM"
    },

    # --- NETWORK WORM ---
    {
        "category": "Network Worm",
        "family": "Worm.Generic.AutoSpreader",
        "rule_id": "WORM_LATERAL_SPREAD",
        "name": "SMB / Network Share Auto-Propagation",
        "desc": "Scans local subnet and copies executable to network shares or ADMIN$ shares",
        "patterns": [b'autorun.inf', b'NetShareEnum', b'WNetAddConnection', b'psexec.exe', b'psexec', b'ADMIN$', b'EternalBlue'],
        "weight": 35,
        "severity": "CRITICAL"
    },

    # --- ADWARE / PUP ---
    {
        "category": "Adware / PUP",
        "family": "Adware.Generic.BrowserInject",
        "rule_id": "ADWARE_INJECT_PATTERNS",
        "name": "Forced Ad Injection & Redirects",
        "desc": "Hooks browser sessions to inject third-party advertising or redirects",
        "patterns": [b'adserver', b'clicktracker', b'popunder', b'affiliate_track', b'trafficjunky'],
        "weight": 20,
        "severity": "MEDIUM"
    }
]

def get_file_type(file_bytes, filename=""):
    """Accurately identifies file format via magic bytes and extensions."""
    if file_bytes.startswith(b'MZ'):
        return 'Windows PE Executable'
    elif file_bytes.startswith(b'\x7fELF'):
        return 'Linux ELF Binary'
    elif file_bytes.startswith(b'%PDF'):
        return 'PDF Document'
    elif file_bytes.startswith(b'\x89PNG'):
        return 'PNG Image'
    elif file_bytes.startswith(b'\xff\xd8\xff'):
        return 'JPEG Image'
    elif file_bytes.startswith(b'PK\x03\x04'):
        return 'ZIP / Office Archive'
    elif file_bytes.startswith(b'#!'):
        return 'Script / Shell Executable'

    ext = os.path.splitext(filename.lower())[1]
    if ext in ['.ps1', '.bat', '.cmd']:
        return 'Windows Script / Batch'
    elif ext in ['.py']:
        return 'Python Script'
    elif ext in ['.txt', '.csv', '.json', '.xml']:
        return 'Plain Text Document'

    try:
        sample = file_bytes[:1024].decode('utf-8')
        if all(ord(c) < 128 for c in sample):
            return 'Plain Text / Script'
    except UnicodeDecodeError:
        pass

    return 'Unknown / Binary Data'

def analyze_file(filename, file_bytes):
    hashes = calculate_hashes(file_bytes)
    file_type = get_file_type(file_bytes, filename)
    size = len(file_bytes)
    iocs = detect_iocs(file_bytes)

    static_details = []
    matched_rules = []
    category_scores = {
        "Ransomware": 0,
        "Spyware / InfoStealer": 0,
        "Keylogger": 0,
        "Trojan / Dropper": 0,
        "Network Worm": 0,
        "Adware / PUP": 0
    }
    category_families = {}

    static_details.append(f"[INFO] Analyzed File: {filename} ({size} bytes)")
    static_details.append(f"[INFO] Detected File Format: {file_type}")
    static_details.append(f"[INFO] MD5: {hashes['md5']}")
    static_details.append(f"[INFO] SHA-256: {hashes['sha256']}")

    # 1. EICAR Test Check (supports standard & safe simulation)
    if EICAR_PATTERN in file_bytes or b'EICAR-STANDARD-ANTIVIRUS-TEST' in file_bytes:
        static_details.append("[ALERT] Exact signature match: EICAR Standard Anti-Virus Test Pattern.")
        static_details.append("[INFO] File is non-malicious but standardized for AV engine validation.")
        return {
            "filename": filename,
            "size": size,
            "type": file_type,
            "md5": hashes['md5'],
            "sha256": hashes['sha256'],
            "score": 100,
            "malware_type": "EICAR Standard Test File",
            "malware_family": "Test.EICAR.Standard-AV-Test",
            "severity": "CRITICAL",
            "matched_rules": [{
                "rule_id": "TEST_EICAR_SIG",
                "name": "EICAR Anti-Virus Test Signature",
                "desc": "Standard industry benign test pattern used worldwide to verify AV and scanner detection pipelines",
                "severity": "CRITICAL"
            }],
            "recommendation": "This is the official benign EICAR antivirus test file. It is non-harmful and exclusively used to verify that security scanners correctly identify threat signatures.",
            "static_details": static_details,
            "iocs": iocs
        }

    is_executable = (file_type in ['Windows PE Executable', 'Linux ELF Binary', 'Windows Script / Batch'])
    if is_executable:
        static_details.append("[INFO] Parsing binary structure and executable headers...")

    lower_bytes = file_bytes.lower()
    for rule in HEURISTIC_RULES:
        found_patterns = []
        for pattern in rule["patterns"]:
            if pattern.lower() in lower_bytes:
                found_patterns.append(pattern.decode('utf-8', errors='ignore'))

        if found_patterns:
            category = rule["category"]
            weight = rule["weight"]
            category_scores[category] = category_scores.get(category, 0) + weight
            if category not in category_families:
                category_families[category] = rule["family"]

            matched_rules.append({
                "rule_id": rule["rule_id"],
                "name": rule["name"],
                "desc": rule["desc"],
                "severity": rule["severity"],
                "category": category,
                "matches": found_patterns[:3]
            })

            tag = "[ALERT]" if rule["severity"] == "CRITICAL" else "[WARN]"
            static_details.append(f"{tag} Rule Matched [{rule['name']}]: {rule['desc']} (Patterns: {', '.join(found_patterns[:2])})")

    if len(iocs) > 0:
        static_details.append(f"[WARN] Discovered {len(iocs)} Indicators of Compromise embedded in binary/strings.")
        for ioc in iocs[:5]:
            static_details.append(f"  -> IoC [{ioc['type'].upper()}]: {ioc['value']}")

    max_category = None
    max_cat_score = 0
    for cat, cscore in category_scores.items():
        if cscore > max_cat_score:
            max_cat_score = cscore
            max_category = cat

    total_score = max_cat_score
    if is_executable and total_score > 0:
        total_score += 15
    if len(iocs) > 0:
        total_score += min(len(iocs) * 10, 30)

    total_score = min(max(total_score, 0), 100)

    if total_score >= 60 and max_category:
        malware_type = max_category
        malware_family = category_families.get(max_category, f"{max_category}.Generic")
        severity = "CRITICAL" if total_score >= 80 else "HIGH"
    elif total_score >= 30 and max_category:
        malware_type = f"Suspicious ({max_category})"
        malware_family = category_families.get(max_category, f"Suspicious.{max_category}")
        severity = "MEDIUM"
    elif total_score >= 20:
        malware_type = "Suspicious Artifact"
        malware_family = "Generic.Suspicious"
        severity = "LOW"
    else:
        malware_type = "Clean / Benign"
        malware_family = "Benign.NoThreatsFound"
        severity = "CLEAN"
        total_score = 0
        static_details.append("[INFO] No malicious signatures or suspicious heuristics identified.")
        static_details.append("[INFO] File appears benign and safe for standard handling.")

    if "Ransomware" in malware_type:
        recommendation = (
            "CRITICAL RANSOMWARE THREAT DETECTED! Immediately disconnect the affected workstation "
            "from all local networks and Wi-Fi to stop lateral spread. Do NOT pay any extortion ransom. "
            "Verify offline immutable backups, block discovered C2 IPs/domains at perimeter firewalls, "
            "and preserve memory dumps for incident response."
        )
    elif "Spyware" in malware_type or "InfoStealer" in malware_type:
        recommendation = (
            "HIGH-RISK INFOSTEALER DETECTED! Threat specifically targets saved browser passwords, "
            "crypto wallets, and DPAPI session credentials. Immediately terminate all active web sessions, "
            "force password resets across organizational accounts, invalidate active 2FA/API tokens, and "
            "audit crypto wallet transaction history."
        )
    elif "Keylogger" in malware_type:
        recommendation = (
            "ACTIVE KEYLOGGER DETECTED! Keystroke hook APIs and keyboard polling detected. All credentials, "
            "messages, and sensitive inputs typed on this system may be compromised. Disconnect the machine, "
            "inspect running hooks with anti-rootkit utilities, and reset all account credentials from a known clean device."
        )
    elif "Trojan" in malware_type:
        recommendation = (
            "TROJAN / DROPPER DETECTED! Process memory injection and payload dropper patterns identified. "
            "Terminate suspicious child processes (powershell, cmd, bitsadmin), inspect Run registry persistence keys, "
            "and blacklist the discovered download URLs/IP addresses in proxy and DNS filters."
        )
    elif "Worm" in malware_type:
        recommendation = (
            "NETWORK WORM PROPAGATION DETECTED! Disable network file shares (SMB/ADMIN$) and block lateral ports "
            "(TCP 445/139). Scan connected removable storage media and inspect autorun persistence points across the subnet."
        )
    elif "Adware" in malware_type:
        recommendation = (
            "POTENTIALLY UNWANTED PROGRAM (PUP) / ADWARE! Review installed browser extensions and scheduled tasks. "
            "Remove unauthorized application packages and reset browser search provider preferences."
        )
    else:
        recommendation = (
            "No known malicious signatures or exploit heuristics were identified during static analysis. "
            "The file exhibits standard benign attributes. For unknown executables, sandboxed dynamic analysis is always recommended."
        )

    if total_score >= 70:
        iocs.append({"type": "hash", "value": hashes['sha256']})

    return {
        "filename": filename,
        "size": size,
        "type": file_type,
        "md5": hashes['md5'],
        "sha256": hashes['sha256'],
        "score": total_score,
        "malware_type": malware_type,
        "malware_family": malware_family,
        "severity": severity,
        "matched_rules": matched_rules,
        "recommendation": recommendation,
        "static_details": static_details,
        "iocs": iocs
    }

