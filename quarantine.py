import shutil
import os

QUARANTINE_DIR = "quarantine"

def quarantine_file(file_path):
    if not os.path.exists(QUARANTINE_DIR):
        os.mkdir(QUARANTINE_DIR)

    try:
        file_name = os.path.basename(file_path)
        new_path = os.path.join(QUARANTINE_DIR, file_name + ".quarantined")
        shutil.move(file_path, new_path)
        return new_path
    except:
        return None
