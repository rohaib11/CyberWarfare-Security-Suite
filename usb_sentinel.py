import psutil
import time
import os
from PyQt5.QtCore import QThread, pyqtSignal

class USBSentinel(QThread):
    usb_detected = pyqtSignal(str) # Signal to send back to Main App

    def __init__(self):
        super().__init__()
        self.running = True
        # Memorize current drives (e.g., {'C:\\', 'D:\\'})
        self.existing_drives = self.get_connected_drives()

    def get_connected_drives(self):
        """Returns a set of currently connected drive letters."""
        drives = set()
        try:
            for part in psutil.disk_partitions():
                if 'removable' in part.opts or 'cdrom' in part.opts:
                    drives.add(part.device)
        except Exception:
            pass
        return drives

    def run(self):
        while self.running:
            try:
                current_drives = self.get_connected_drives()
                
                # Check for NEW drives (Current - Old)
                new_drives = current_drives - self.existing_drives
                
                for drive in new_drives:
                    # We found a new USB!
                    self.usb_detected.emit(drive)
                
                self.existing_drives = current_drives
                time.sleep(2) # Check every 2 seconds
            except Exception:
                pass

    def stop(self):
        self.running = False