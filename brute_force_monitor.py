import win32evtlog
import time
from PyQt5.QtCore import QThread, pyqtSignal

class BruteForceMonitor(QThread):
    intrusion_detected = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.running = True
        self.server = 'localhost'
        self.log_type = 'Security'

    def run(self):
        try:
            # Connect to Windows Event Log
            hand = win32evtlog.OpenEventLog(self.server, self.log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            last_time = time.time()

            while self.running:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if events:
                    for event in events:
                        # Event ID 4625 = Failed Login Attempt
                        if event.EventID == 4625:
                            # Check if it is a NEW event
                            event_time = event.TimeGenerated.timestamp()
                            if event_time > last_time:
                                try:
                                    # Try to get the username (usually index 5 or 0 depending on OS version)
                                    user = event.StringInserts[5] if len(event.StringInserts) > 5 else "Unknown"
                                    self.intrusion_detected.emit(f"🚨 BRUTE FORCE ATTEMPT: User '{user}' failed login!")
                                except:
                                    self.intrusion_detected.emit("🚨 FAILED LOGIN DETECTED!")
                                
                                last_time = event_time
                
                time.sleep(2) # Check every 2 seconds
        except Exception as e:
            # Silently fail if admin rights are missing (Event Log requires Admin)
            pass

    def stop(self):
        self.running = False