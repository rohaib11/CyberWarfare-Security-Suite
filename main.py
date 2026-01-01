import sys
import psutil
import os
from PyQt5.QtWidgets import QApplication, QFileDialog, QMessageBox, QSystemTrayIcon, QMenu, QAction, QStyle
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt

# UI Import
from ui import ModernUI

# Feature Imports
from monitor_engine import SystemMonitor
from process_scanner import scan_processes, kill_process
from hash_checker import calculate_hash, check_virustotal
from startup_checker import check_startup
from network_scanner import scan_network, scan_lan_devices, set_internet_state
from secure_vault import encrypt_file, decrypt_file
from ransomware_guard import start_ransomware_watch
from identity_checker import check_email_leak
from report_generator import generate_security_report
from firewall_manager import block_ip_address
from tools_manager import clean_system_junk, check_password_strength, secure_file_shredder
from database import init_db, add_log
from yara_scanner import scan_file_with_yara
from quarantine_manager import quarantine_file, restore_file, get_quarantined_files
from usb_sentinel import USBSentinel
from privacy_monitor import check_privacy
from packet_sniffer import PacketSniffer # NEW
from brute_force_monitor import BruteForceMonitor # NEW

class SecurityApp(ModernUI):
    def __init__(self):
        super().__init__()
        init_db()

        # --- SYSTEM TRAY SETUP ---
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        tray_menu = QMenu()
        show_action = QAction("Open Dashboard", self)
        show_action.triggered.connect(self.show)
        quit_action = QAction("Exit", self)
        quit_action.triggered.connect(self.quit_app)
        tray_menu.addAction(show_action)
        tray_menu.addAction(quit_action)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        self.tray_icon.activated.connect(self.tray_icon_activated)

        # --- UI CONNECTIONS ---
        self.sidebar.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.sidebar.itemClicked.connect(self.update_header)

        # --- ENGINES ---
        self.monitor = SystemMonitor()
        self.monitor.update_log.connect(self.update_dashboard_log)
        self.monitor.start()
        
        self.usb_watch = USBSentinel()
        self.usb_watch.usb_detected.connect(self.handle_usb_insertion)
        self.usb_watch.start()

        self.ransom_observer = None

        # --- NEW ENGINES (V5.0) ---
        # 1. Brute Force Monitor (Always On)
        self.brute_monitor = BruteForceMonitor()
        self.brute_monitor.intrusion_detected.connect(self.handle_intrusion)
        self.brute_monitor.start()

        # 2. Packet Sniffer (On Demand)
        self.sniffer = PacketSniffer()
        self.sniffer.packet_captured.connect(self.update_sniffer_log)
        self.sniffing = False

        # --- BUTTON CONNECTIONS ---
        self.dash_btn_scan.clicked.connect(self.run_quick_scan)
        self.rt_toggle.toggled.connect(self.toggle_realtime)
        self.lock_toggle.toggled.connect(self.toggle_lockdown)
        
        self.vpn_toggle.toggled.connect(self.toggle_vpn)
        self.btn_panic.clicked.connect(self.toggle_panic_mode)
        self.panic_mode = False
        
        self.btn_proc.clicked.connect(self.run_proc_scan)
        self.btn_file.clicked.connect(self.run_file_scan)
        self.btn_start.clicked.connect(self.run_startup_scan)
        self.btn_kill.clicked.connect(self.run_kill_process)
        self.btn_net.clicked.connect(self.run_net_scan)
        self.btn_lan.clicked.connect(self.run_lan_scan)
        self.btn_sniffer.clicked.connect(self.toggle_sniffer) # NEW
        self.btn_block.clicked.connect(self.run_block_ip)
        self.btn_encrypt.clicked.connect(self.run_encrypt)
        self.btn_decrypt.clicked.connect(self.run_decrypt)
        self.btn_check_leak.clicked.connect(self.run_leak_check)
        self.btn_clean.clicked.connect(self.run_junk_cleaner)
        self.btn_shred.clicked.connect(self.run_shredder)
        self.btn_check_pass.clicked.connect(self.run_pass_checker)
        self.btn_report.clicked.connect(self.run_generate_report)

        # --- QUARANTINE BUTTONS ---
        self.btn_quarantine.clicked.connect(self.run_quarantine)
        self.btn_restore.clicked.connect(self.run_restore)
        self.refresh_quarantine_list()
        self.last_scanned_file = None

        add_log("Application Started")

    # --- TRAY FUNCTIONS ---
    def closeEvent(self, event):
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            "PC Security Monitor",
            "Running in background. Double-click tray icon to open.",
            QSystemTrayIcon.Information,
            2000
        )

    def tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()

    def quit_app(self):
        self.monitor.stop()
        self.usb_watch.stop()
        self.brute_monitor.stop() # Stop Brute Force Monitor
        if self.sniffer.isRunning(): self.sniffer.stop() # Stop Sniffer
        if self.ransom_observer: self.ransom_observer.stop()
        QApplication.quit()

    # --- UI HELPERS ---
    def update_header(self, item):
        self.header_label.setText(item.text().strip().upper())

    def update_dashboard_log(self, message):
        self.live_log.append(f"⏱ {message}")
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        self.system_graph.update_graph(cpu, ram)
        
        if "ALERT" in message or "DANGER" in message or "ANOMALY" in message or "BLOCKED" in message:
             self.status_icon.setText("⚠️")
             self.status_text.setText("Threats Detected!")

    # --- NEW FEATURE HANDLERS ---
    def handle_intrusion(self, msg):
        """Called when someone fails a login."""
        self.live_log.append(f"🚨 {msg}")
        self.status_text.setText("SECURITY BREACH!")
        self.status_icon.setText("🛑")
        
        # Auto-Lockdown on breach
        if not self.monitor.lockdown_mode:
            self.lock_toggle.setChecked(True) 
            self.live_log.append("🏰 AUTO-LOCKDOWN ENABLED DUE TO INTRUSION")

    def toggle_sniffer(self):
        if not self.sniffing:
            self.sniffer = PacketSniffer() # Re-init thread
            self.sniffer.packet_captured.connect(self.update_sniffer_log)
            self.sniffer.start()
            self.btn_sniffer.setText("⬛ Stop Sniffer")
            self.btn_sniffer.setStyleSheet("background-color: #555;")
            self.sniffer_output.append("--- WIRETAP STARTED ---")
            self.sniffing = True
        else:
            self.sniffer.stop()
            self.btn_sniffer.setText("🔴 Start Packet Sniffer")
            self.btn_sniffer.setStyleSheet("background-color: #c0392b; font-weight: bold;")
            self.sniffer_output.append("--- WIRETAP STOPPED ---")
            self.sniffing = False

    def update_sniffer_log(self, packet_text):
        self.sniffer_output.append(packet_text)
        cursor = self.sniffer_output.textCursor()
        cursor.movePosition(cursor.End)
        self.sniffer_output.setTextCursor(cursor)

    # --- EXISTING HANDLERS ---
    def handle_usb_insertion(self, drive_letter):
        self.live_log.append(f"🔌 USB DETECTED: {drive_letter}")
        self.status_text.setText(f"Scanning USB: {drive_letter}...")
        QApplication.processEvents()
        
        autorun_path = os.path.join(drive_letter, "autorun.inf")
        if os.path.exists(autorun_path):
            self.live_log.append("🚨 CRITICAL: Malicious 'autorun.inf' found on USB!")
            QMessageBox.warning(self, "USB THREAT", f"Dangerous file detected on {drive_letter}!")
        
        try:
            files = os.listdir(drive_letter)[:5]
            for f in files:
                self.live_log.append(f"Scanning USB File: {f}...")
        except Exception as e:
            self.live_log.append(f"Error reading USB: {e}")
            
        self.live_log.append("✅ USB Scan Complete.")
        self.status_text.setText("System Secure")

    def toggle_panic_mode(self):
        if not self.panic_mode:
            msg = set_internet_state(enable=False)
            self.live_log.append(msg)
            self.btn_panic.setText("RESTORE NET")
            self.btn_panic.setStyleSheet("background-color: #00c853; color: white; font-weight: bold;")
            self.status_text.setText("⛔ INTERNET DISABLED")
            self.panic_mode = True
        else:
            msg = set_internet_state(enable=True)
            self.live_log.append(msg)
            self.btn_panic.setText("🚨 KILL SWITCH")
            self.btn_panic.setStyleSheet("background-color: #ff0000; color: white; font-weight: bold;")
            self.status_text.setText("System Secure")
            self.panic_mode = False

    def toggle_lockdown(self, checked):
        if checked:
            self.monitor.enable_lockdown()
            self.lock_label.setText("🏰 Fortress Mode (ACTIVE)")
            self.lock_label.setStyleSheet("font-weight: bold; color: #e74c3c;")
            self.live_log.append("🔒 SYSTEM LOCKED: No new apps can start.")
        else:
            self.monitor.disable_lockdown()
            self.lock_label.setText("🏰 Fortress Mode (Block New Apps)")
            self.lock_label.setStyleSheet("font-weight: bold; color: #f1c40f;")
            self.live_log.append("🔓 System Unlocked.")

    def run_quick_scan(self):
        self.live_log.append("--- Starting Quick System Scan ---")
        QApplication.processEvents()
        self.run_proc_scan()
        self.run_startup_scan()
        self.live_log.append("--- Quick Scan Complete ---")
        self.status_icon.setText("✅")
        self.status_text.setText("System Secure")

    def toggle_realtime(self, checked):
        if checked:
            self.monitor.start()
            if not self.ransom_observer:
                 self.ransom_observer = start_ransomware_watch(self.update_dashboard_log)
            self.rt_label.setText("Real-Time Protection: ACTIVE")
            self.live_log.append("✔ Real-Time Engines Enabled.")
        else:
            self.monitor.stop()
            if self.ransom_observer:
                self.ransom_observer.stop()
                self.ransom_observer = None
            self.rt_label.setText("Real-Time Protection: PAUSED")
            self.live_log.append("⚠ Real-Time Engines Paused.")

    def toggle_vpn(self, checked):
        if checked:
            self.vpn_status.setText("Status: Connected to Stockholm (Secure)")
            self.vpn_status.setStyleSheet("color: #27ae60;")
            self.live_log.append("🔒 VPN Connected securely.")
        else:
            self.vpn_status.setText("Status: Disconnected (Your IP is exposed)")
            self.vpn_status.setStyleSheet("color: #c0392b;")
            self.live_log.append("🔓 VPN Disconnected.")

    def run_proc_scan(self):
        self.scan_output.clear()
        self.scan_output.append("Scanning processes...")
        results = scan_processes()
        if results: self.scan_output.append("\n".join(results))
        else: self.scan_output.append("✔ System Clean.")

    def run_file_scan(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
        if file_path:
            self.last_scanned_file = file_path 
            self.scan_output.append(f"Analyzing: {file_path}")
            QApplication.processEvents()
            
            f_hash = calculate_hash(file_path)
            self.scan_output.append(f"Hash: {f_hash}")
            c_res = check_virustotal(f_hash)
            self.scan_output.append(f"☁ Cloud Check: {c_res}")
            
            self.scan_output.append("🔍 Running YARA Pattern Match...")
            QApplication.processEvents()
            yara_res = scan_file_with_yara(file_path)
            self.scan_output.append(f"🧬 YARA Analysis: {yara_res}")
            
            if "THREAT" in yara_res or "DANGER" in c_res:
                self.scan_output.append("\n⚠ RECOMMENDATION: Click 'Quarantine' immediately!")
            
            self.scan_output.append("-" * 30)

    def run_quarantine(self):
        if self.last_scanned_file:
            success, msg = quarantine_file(self.last_scanned_file)
            self.scan_output.append(f"\n🛡 JAIL: {msg}")
            if success:
                self.last_scanned_file = None
                self.refresh_quarantine_list()
        else:
            self.scan_output.append("\n⚠ No file selected to quarantine. Scan a file first.")

    def run_restore(self):
        file_to_restore = self.q_list.currentText()
        if file_to_restore:
            success, msg = restore_file(file_to_restore)
            self.scan_output.append(f"\n♻ RESTORE: {msg}")
            self.refresh_quarantine_list()

    def refresh_quarantine_list(self):
        self.q_list.clear()
        files = get_quarantined_files()
        self.q_list.addItems(files)

    def run_kill_process(self):
        pid = self.pid_input.text()
        if pid.isdigit():
            success, msg = kill_process(int(pid))
            self.scan_output.append(msg)

    def run_startup_scan(self):
        self.scan_output.append("\n".join(check_startup()))

    def run_net_scan(self):
        self.net_output.clear()
        self.net_output.append("\n".join(scan_network()))

    def run_lan_scan(self):
        self.net_output.clear()
        self.net_output.append("Scanning Local Network (ARP Table)...")
        QApplication.processEvents()
        devices = scan_lan_devices()
        self.net_output.append("\n".join(devices))

    def run_block_ip(self):
        ip = self.ip_input.text().strip()
        parts = ip.split(".")
        if len(parts) == 4 and all(part.isdigit() for part in parts):
             self.net_output.append(f"Attempting to block {ip}...")
             QApplication.processEvents()
             success, msg = block_ip_address(ip)
             self.net_output.append(msg)
        else:
             self.net_output.append("⚠ Error: Invalid IP Address.")

    def run_encrypt(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
        if file_path:
            success, msg = encrypt_file(file_path)
            self.vault_output.append(msg)

    def run_decrypt(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Locked File", "", "Locked (*.locked)")
        if file_path:
            success, msg = decrypt_file(file_path)
            self.vault_output.append(msg)

    def run_leak_check(self):
        email = self.email_input.text()
        if "@" in email:
            self.id_output.append(f"Scanning for: {email}...")
            QApplication.processEvents()
            result = check_email_leak(email)
            self.id_output.append(result)

    def run_junk_cleaner(self):
         self.tools_output.append(clean_system_junk())

    def run_shredder(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to DESTROY", "", "All Files (*)")
        if file_path:
            confirm = QMessageBox.question(
                self, "Confirm Shred", 
                f"⚠ PERMANENTLY DELETE?\n\n{file_path}\n\nThis cannot be undone!",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if confirm == QMessageBox.Yes:
                self.tools_output.append(f"Shredding: {file_path}...")
                QApplication.processEvents()
                result = secure_file_shredder(file_path)
                self.tools_output.append(result)

    def run_pass_checker(self):
         self.tools_output.append(check_password_strength(self.pass_input.text()))

    def run_generate_report(self):
        logs = self.live_log.toPlainText().split('\n')
        try:
            path = generate_security_report(logs)
            QMessageBox.information(self, "Report Ready", f"Saved to:\n{path}")
        except Exception as e:
             QMessageBox.critical(self, "Error", str(e))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    window = SecurityApp()
    window.show()
    sys.exit(app.exec_())