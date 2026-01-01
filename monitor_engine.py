from PyQt5.QtCore import QThread, pyqtSignal
import psutil
import time
from ai_brain import AIEngine
from privacy_monitor import check_privacy
import os
import hashlib

# Dangerous patterns
SUSPICIOUS_PARENTS = {
    "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
    "excel.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
    "chrome.exe": ["cmd.exe", "powershell.exe"],
    "explorer.exe": ["powershell.exe"]
}
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"

class SystemMonitor(QThread):
    update_log = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.ai = AIEngine()
        self.hosts_hash = self.get_hosts_hash()
        
        # LOCKDOWN VARIABLES
        self.lockdown_mode = False
        self.allowed_pids = set()

    def get_hosts_hash(self):
        if os.path.exists(HOSTS_PATH):
            try:
                with open(HOSTS_PATH, "rb") as f:
                    return hashlib.md5(f.read()).hexdigest()
            except:
                return None
        return None

    def enable_lockdown(self):
        """Snapshot current processes and enable Zero-Trust."""
        self.allowed_pids = {p.pid for p in psutil.process_iter()}
        self.lockdown_mode = True
        self.update_log.emit("🏰 FORTRESS MODE ENABLED: New processes will be blocked.")

    def disable_lockdown(self):
        self.lockdown_mode = False
        self.update_log.emit("🔓 Fortress Mode Disabled.")

    def run(self):
        self.running = True
        
        while self.running:
            try:
                # --- 1. PRIVACY MONITOR ---
                privacy_alerts = check_privacy()
                for alert in privacy_alerts:
                    self.update_log.emit(f"🕵️ SPY ALERT: {alert}")

                # --- 2. FORTRESS MODE (LOCKDOWN) ---
                if self.lockdown_mode:
                    for proc in psutil.process_iter(['pid', 'name']):
                        if proc.pid not in self.allowed_pids:
                            try:
                                proc.kill() # INSTANTLY KILL NEW PROCESS
                                self.update_log.emit(f"🛡 BLOCKED: {proc.info['name']} (Lockdown Active)")
                            except:
                                pass

                # --- 3. EXISTING CHECKS (Behavior, Hosts, AI) ---
                # Check Behavioral Heuristics
                for proc in psutil.process_iter(['pid', 'name', 'ppid']):
                    try:
                        name = proc.info['name'].lower()
                        parent = psutil.Process(proc.info['ppid'])
                        parent_name = parent.name().lower()
                        if parent_name in SUSPICIOUS_PARENTS:
                            if name in SUSPICIOUS_PARENTS[parent_name]:
                                self.update_log.emit(f"🚨 BEHAVIOR ALERT: {parent_name} spawned {name}!")
                    except:
                        continue

                # Check Hosts File
                current_hash = self.get_hosts_hash()
                if current_hash and self.hosts_hash and current_hash != self.hosts_hash:
                    self.update_log.emit("⚠ HOSTS FILE MODIFIED!")
                    self.hosts_hash = current_hash

                # Check AI
                cpu = psutil.cpu_percent(interval=1)
                ram = psutil.virtual_memory().percent
                disk = psutil.disk_io_counters()
                
                self.ai.add_data_point(cpu, ram, disk.read_count, disk.write_count)
                status = self.ai.predict_anomaly(cpu, ram, disk.read_count, disk.write_count)
                if status == "ANOMALY":
                     self.update_log.emit(f"🧠 AI ALERT: Abnormal CPU ({cpu}%)")

            except Exception as e:
                pass
                
            time.sleep(1) # Scan interval

    def stop(self):
        self.running = False