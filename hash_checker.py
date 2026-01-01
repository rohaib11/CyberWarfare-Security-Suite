import hashlib
import requests
import os

# ---------------- CONFIGURATION ----------------
# To make this work for real, you need a FREE API Key from VirusTotal.
# 1. Go to: https://www.virustotal.com/gui/join-us
# 2. Sign up and get your API Key.
# 3. Paste it below inside the quotes.
API_KEY = "089eecc8886af72f632025a3d97eda95a8e4cab00b1ef060d6910943b4e87813"
# -----------------------------------------------

def calculate_hash(file_path):
    """Calculates the unique SHA-256 fingerprint of a file."""
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            # Read file in chunks so we don't crash RAM with huge files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return None

def check_virustotal(file_hash):
    """Asks the VirusTotal Cloud if this hash is malicious."""
    if not file_hash:
        return "Error: Could not calculate hash."
        
    if API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return "⚠ API Key Missing (Edit hash_checker.py)"

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            
            if malicious > 0:
                return f"❌ DANGER: Detected by {malicious} antiviruses!"
            else:
                return "✔ Clean (No threats found in cloud database)"
        elif response.status_code == 404:
            return "❓ Unknown File (Not in VirusTotal database)"
        else:
            return f"⚠ Cloud Error: {response.status_code}"
            
    except Exception as e:
        return f"Connection Failed: {str(e)}"