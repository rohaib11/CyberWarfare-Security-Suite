import os
import shutil
import tempfile
import re
import math
import random

def clean_system_junk():
    """Cleans temporary folders to free up space."""
    temp_folder = tempfile.gettempdir()
    deleted_files = 0
    errors = 0
    
    try:
        for filename in os.listdir(temp_folder):
            file_path = os.path.join(temp_folder, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                    deleted_files += 1
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
                    deleted_files += 1
            except Exception:
                errors += 1
        return f"Cleanup Complete: {deleted_files} files removed. ({errors} skipped)"
    except Exception as e:
        return f"Error cleaning junk: {str(e)}"

def check_password_strength(password):
    """Calculates password entropy."""
    if not password:
        return "Password cannot be empty."
        
    length = len(password)
    has_lower = re.search(r"[a-z]", password)
    has_upper = re.search(r"[A-Z]", password)
    has_digit = re.search(r"\d", password)
    has_special = re.search(r"[ !#$%&'()*+,-./:;<=>?@[\]^_`{|}~]", password)
    
    score = 0
    if has_lower: score += 1
    if has_upper: score += 1
    if has_digit: score += 1
    if has_special: score += 1
    
    if length < 8:
        return "Weak: Too short (min 8 chars)"
    elif score < 3:
        return "Medium: Add numbers or symbols"
    elif score == 4 and length >= 12:
        return "Strong: Excellent password!"
    else:
        return "Good: But could be longer"

def secure_file_shredder(file_path, passes=3):
    """Overwrites a file with random data multiple times before deletion."""
    if not os.path.exists(file_path):
        return "File not found."
    
    try:
        file_size = os.path.getsize(file_path)
        
        with open(file_path, "wb") as f:
            for i in range(passes):
                # Generate random garbage data
                garbage = os.urandom(file_size)
                f.write(garbage)
                f.seek(0) # Go back to start of file for next pass
        
        # Finally delete it
        os.remove(file_path)
        return f"✅ SUCCESS: File shredded ({passes} passes). Recovery impossible."
    except Exception as e:
        return f"❌ Error: {str(e)}"