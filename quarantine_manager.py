import os
import shutil
import json
from datetime import datetime

QUARANTINE_DIR = "Quarantine_Jail"
DB_FILE = os.path.join(QUARANTINE_DIR, "quarantine_log.json")

# Ensure folders exist
if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            return json.load(f)
    return {}

def save_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=4)

def quarantine_file(file_path):
    """Moves a file to the jail and locks it."""
    if not os.path.exists(file_path):
        return False, "File not found."

    try:
        # Generate safe name
        filename = os.path.basename(file_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = f"{filename}_{timestamp}.virus" # Rename extension so it can't run
        dest_path = os.path.join(QUARANTINE_DIR, safe_name)

        # Move file
        shutil.move(file_path, dest_path)

        # Log details for restoring later
        db = load_db()
        db[safe_name] = {
            "original_path": file_path,
            "quarantined_at": str(datetime.now())
        }
        save_db(db)

        return True, f"File jailed as {safe_name}"
    except Exception as e:
        return False, str(e)

def restore_file(safe_name):
    """Moves a file back to its original location."""
    db = load_db()
    if safe_name not in db:
        return False, "Record not found in database."

    info = db[safe_name]
    src_path = os.path.join(QUARANTINE_DIR, safe_name)
    original_path = info["original_path"]

    try:
        if os.path.exists(src_path):
            shutil.move(src_path, original_path)
            
            # Remove from DB
            del db[safe_name]
            save_db(db)
            return True, f"Restored to {original_path}"
        else:
            return False, "Quarantined file missing from disk."
    except Exception as e:
        return False, str(e)

def get_quarantined_files():
    """Returns list of currently jailed files."""
    db = load_db()
    return list(db.keys())