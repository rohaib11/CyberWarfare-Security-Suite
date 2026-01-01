import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Create a decoy folder in the user's home directory
USER_HOME = os.path.expanduser("~")
TRAP_DIR = os.path.join(USER_HOME, "My_Secret_Documents")

class RansomwareHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback

    def on_modified(self, event):
        self.callback(f"⚠ RANSOMWARE ALERT: File modified in trap folder: {event.src_path}")

    def on_deleted(self, event):
        self.callback(f"⚠ RANSOMWARE ALERT: File deleted in trap folder: {event.src_path}")

def start_ransomware_watch(callback_function):
    # 1. Create the Trap Folder if it doesn't exist
    if not os.path.exists(TRAP_DIR):
        os.makedirs(TRAP_DIR)
        # Create fake bait files
        with open(os.path.join(TRAP_DIR, "bank_passwords.txt"), "w") as f:
            f.write("This is a bait file for ransomware.")
        with open(os.path.join(TRAP_DIR, "family_photos.jpg"), "w") as f:
            f.write("Fake image data.")

    # 2. Start Watching
    event_handler = RansomwareHandler(callback_function)
    observer = Observer()
    observer.schedule(event_handler, path=TRAP_DIR, recursive=False)
    observer.start()
    return observer