from PyQt5.QtWidgets import *
from PyQt5.QtGui import QFont, QIcon, QColor, QPixmap
from PyQt5.QtCore import Qt, QSize
from graph_widget import LiveGraph

class CardWidget(QFrame):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            CardWidget {
                background-color: #2a2e3b;
                border-radius: 12px;
                border: 1px solid #3a3f4b;
                padding: 20px;
            }
            QLabel[title="true"] {
                font-size: 18px;
                font-weight: bold;
                color: #ffffff;
                margin-bottom: 10px;
            }
        """)
        self.layout = QVBoxLayout(self)
        self.title_label = QLabel(title)
        self.title_label.setProperty("title", True)
        self.layout.addWidget(self.title_label)
        self.content_layout = QVBoxLayout()
        self.layout.addLayout(self.content_layout)

    def add_widget(self, widget):
        self.content_layout.addWidget(widget)
    
    def add_layout(self, layout):
        self.content_layout.addLayout(layout)


class ModernUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PC Security Monitor - Cyber Warfare Edition")
        self.setGeometry(100, 100, 1280, 850)
        
        self.setStyleSheet("""
            QMainWindow { background-color: #181818; }
            QWidget { color: #e0e0e0; font-family: 'Segoe UI', Arial; }
            
            QListWidget {
                background-color: #202020;
                border-right: 1px solid #333;
                outline: none;
                font-size: 15px;
            }
            QListWidget::item {
                padding: 18px;
                border-radius: 8px;
                margin: 5px 10px;
                color: #aaaaaa;
            }
            QListWidget::item:selected {
                background-color: #007acc;
                color: white;
            }
            QListWidget::item:hover {
                background-color: #2d2d2d;
            }

            QMenu {
                background-color: #2d2d2d;
                border: 1px solid #555;
            }
            QMenu::item {
                background-color: transparent;
                padding: 6px 20px;
                color: white;
            }
            QMenu::item:selected {
                background-color: #007acc;
            }
            
            QPushButton { 
                background-color: #007acc; color: white; border-radius: 6px; 
                padding: 10px 20px; font-weight: 600; font-size: 13px;
                border: none;
            }
            QPushButton:hover { background-color: #0069d9; }
            QPushButton:pressed { background-color: #0056b3; }
            QPushButton#dangerBtn { background-color: #d32f2f; }
            QPushButton#dangerBtn:hover { background-color: #b71c1c; }

            QCheckBox::indicator { width: 44px; height: 24px; border-radius: 12px; }
            QCheckBox::indicator:unchecked { background-color: #4a4a4a; }
            QCheckBox::indicator:checked { background-color: #00c853; }
            
            QLabel { font-size: 14px; color: #cccccc; }
            QTextEdit, QLineEdit, QComboBox { 
                background-color: #252526; color: #00e676; 
                border: 1px solid #3e3e42; border-radius: 6px; padding: 10px;
                selection-background-color: #007acc;
            }
            QLineEdit:focus { border: 1px solid #007acc; }
            
            QGroupBox { 
                border: 1px solid #444; 
                margin-top: 10px; 
                padding-top: 15px; 
                border-radius: 5px;
            }
            QGroupBox::title { color: #00aaff; subcontrol-origin: margin; left: 10px; padding: 0 5px; }
            
            /* Splitter Handle */
            QSplitter::handle { background-color: #444; }
        """)

        self.main_widget = QWidget()
        self.main_layout = QHBoxLayout(self.main_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        self.setCentralWidget(self.main_widget)

        # --- LEFT SIDEBAR ---
        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(260)
        self.sidebar.addItem(QListWidgetItem("  Dashboard"))
        self.sidebar.addItem(QListWidgetItem("  Scanners"))
        self.sidebar.addItem(QListWidgetItem("  Network Guard"))
        self.sidebar.addItem(QListWidgetItem("  Secure Vault"))
        self.sidebar.addItem(QListWidgetItem("  Identity Theft"))
        self.sidebar.addItem(QListWidgetItem("  System Tools"))
        self.sidebar.addItem(QListWidgetItem("  Audit Reports"))
        self.sidebar.setCurrentRow(0) 
        self.main_layout.addWidget(self.sidebar)

        # --- RIGHT CONTENT AREA ---
        self.content_area = QWidget()
        self.content_layout = QVBoxLayout(self.content_area)
        self.content_layout.setContentsMargins(40, 40, 40, 40)
        
        # --- HEADER ---
        self.header_layout = QHBoxLayout()
        self.header_label = QLabel("DASHBOARD")
        self.header_label.setStyleSheet("font-size: 32px; font-weight: 800; color: white; letter-spacing: 1px;")
        
        self.version_label = QLabel("v5.0 WARFARE")
        self.version_label.setStyleSheet("background-color: #333; color: #e74c3c; padding: 5px 12px; border-radius: 15px; font-size: 12px; font-weight: bold;")
        
        self.header_layout.addWidget(self.header_label)
        self.header_layout.addStretch()
        self.header_layout.addWidget(self.version_label)
        self.content_layout.addLayout(self.header_layout)

        self.pages = QStackedWidget()
        self.content_layout.addWidget(self.pages)
        self.main_layout.addWidget(self.content_area)

        # ================= PAGES =================

        # --- PAGE 1: DASHBOARD ---
        self.page_dashboard = QWidget()
        self.dash_layout = QVBoxLayout(self.page_dashboard)
        self.dash_layout.setSpacing(25)

        # Status Card
        self.status_card = CardWidget("System Status")
        self.status_layout = QHBoxLayout()
        self.status_icon = QLabel("✅")
        self.status_icon.setStyleSheet("font-size: 42px;")
        self.status_text = QLabel("System Secure")
        self.status_text.setStyleSheet("font-size: 16px; color: #fff;")
        
        self.status_layout.addWidget(self.status_icon)
        self.status_layout.addWidget(self.status_text)
        self.status_layout.addStretch()
        
        # PANIC BUTTON
        self.btn_panic = QPushButton("🚨 KILL SWITCH")
        self.btn_panic.setFixedSize(120, 40)
        self.btn_panic.setStyleSheet("""
            QPushButton { background-color: #ff0000; color: white; font-weight: bold; border: 2px solid #800000; border-radius: 5px;}
            QPushButton:hover { background-color: #ff4444; }
        """)
        self.status_layout.addWidget(self.btn_panic)
        
        self.dash_btn_scan = QPushButton("Quick Scan")
        self.dash_btn_scan.setMinimumHeight(40)
        self.status_layout.addWidget(self.dash_btn_scan)
        
        self.status_card.add_layout(self.status_layout)
        self.dash_layout.addWidget(self.status_card)

        # Middle Row: Real-Time & Graph
        self.mid_layout = QHBoxLayout()
        self.mid_layout.setSpacing(25)
        
        # Real-Time Engines
        self.rt_card = CardWidget("Real-Time Defense Matrix")
        self.rt_layout = QVBoxLayout() 
        
        # Row 1: General
        row_gen = QHBoxLayout()
        self.rt_label = QLabel("🛡 Malware & Ransomware Guard")
        self.rt_toggle = QCheckBox()
        self.rt_toggle.setChecked(True)
        row_gen.addWidget(self.rt_label)
        row_gen.addStretch()
        row_gen.addWidget(self.rt_toggle)

        # Row 2: Fortress Mode
        row1 = QHBoxLayout()
        self.lock_label = QLabel("🏰 Fortress Mode (Block New Apps)")
        self.lock_label.setStyleSheet("font-weight: bold; color: #f1c40f;")
        self.lock_toggle = QCheckBox() 
        self.lock_toggle.setChecked(False) 
        row1.addWidget(self.lock_label)
        row1.addStretch()
        row1.addWidget(self.lock_toggle)
        
        # Row 3: Privacy
        row2 = QHBoxLayout()
        self.priv_label = QLabel("👁 Spyware Monitor (Cam/Mic)")
        self.priv_label.setStyleSheet("color: #00aaff;")
        self.priv_status = QLabel("WATCHING")
        self.priv_status.setStyleSheet("color: #00ff00; font-weight: bold;")
        row2.addWidget(self.priv_label)
        row2.addStretch()
        row2.addWidget(self.priv_status)

        # Row 4: Behavioral
        row3 = QHBoxLayout()
        self.beh_label = QLabel("🧬 Behavioral Analysis")
        self.beh_label.setStyleSheet("color: #aaa;")
        self.beh_status = QLabel("ACTIVE")
        self.beh_status.setStyleSheet("color: #00ff00; font-weight: bold;")
        row3.addWidget(self.beh_label)
        row3.addStretch()
        row3.addWidget(self.beh_status)

        self.rt_layout.addLayout(row_gen)
        self.rt_layout.addLayout(row1)
        self.rt_layout.addLayout(row2)
        self.rt_layout.addLayout(row3)
        self.rt_card.add_layout(self.rt_layout)
        self.mid_layout.addWidget(self.rt_card, 2)

        self.graph_card = CardWidget("System Load")
        self.system_graph = LiveGraph()
        self.system_graph.setMinimumHeight(150)
        self.graph_card.add_widget(self.system_graph)
        self.mid_layout.addWidget(self.graph_card, 1)
        
        self.dash_layout.addLayout(self.mid_layout)

        # Bottom Row
        self.btm_layout = QHBoxLayout()
        self.btm_layout.setSpacing(25)
        self.vpn_card = CardWidget("Secure VPN")
        self.vpn_layout = QVBoxLayout()
        self.vpn_status = QLabel("Status: Disconnected (Your IP is exposed)")
        self.vpn_toggle = QCheckBox()
        self.vpn_map = QLabel() 
        self.vpn_map.setStyleSheet("background-color: #1a1a1a; border-radius: 8px; min-height: 100px;")
        
        vpn_top = QHBoxLayout()
        vpn_top.addWidget(self.vpn_status)
        vpn_top.addStretch()
        vpn_top.addWidget(self.vpn_toggle)
        self.vpn_layout.addLayout(vpn_top)
        self.vpn_layout.addWidget(self.vpn_map)
        self.vpn_card.add_layout(self.vpn_layout)
        self.btm_layout.addWidget(self.vpn_card)

        self.log_card = CardWidget("Activity Log")
        self.live_log = QTextEdit()
        self.live_log.setReadOnly(True)
        self.log_card.add_widget(self.live_log)
        self.btm_layout.addWidget(self.log_card)
        self.dash_layout.addLayout(self.btm_layout)
        self.pages.addWidget(self.page_dashboard)

        # --- PAGE 2: SCANNERS ---
        self.page_scan = QWidget()
        self.scan_layout = QVBoxLayout(self.page_scan)
        scan_group = QGroupBox("Active Scanning")
        sg_layout = QVBoxLayout()
        btn_box = QHBoxLayout()
        self.btn_proc = QPushButton("Scan Running Processes")
        self.btn_file = QPushButton("Scan Specific File")
        self.btn_start = QPushButton("Check Startup Registry")
        btn_box.addWidget(self.btn_proc)
        btn_box.addWidget(self.btn_file)
        btn_box.addWidget(self.btn_start)
        kill_box = QHBoxLayout()
        self.pid_input = QLineEdit()
        self.pid_input.setPlaceholderText("Enter PID to Terminate")
        self.btn_kill = QPushButton("☠ KILL PROCESS")
        self.btn_kill.setObjectName("dangerBtn")
        kill_box.addWidget(self.pid_input)
        kill_box.addWidget(self.btn_kill)
        sg_layout.addLayout(btn_box)
        sg_layout.addLayout(kill_box)
        scan_group.setLayout(sg_layout)
        self.scan_layout.addWidget(scan_group)
        self.scan_output = QTextEdit()
        self.scan_layout.addWidget(self.scan_output)
        
        q_group = QGroupBox("Quarantine Jail")
        q_group.setStyleSheet("QGroupBox { border: 1px solid #d32f2f; margin-top: 10px; } QGroupBox::title { color: #d32f2f; }")
        q_layout = QHBoxLayout()
        self.q_list = QComboBox()
        self.q_list.setPlaceholderText("Select a file to restore...")
        self.btn_quarantine = QPushButton("☣ Quarantine Selected File") 
        self.btn_quarantine.setStyleSheet("background-color: #d35400;")
        self.btn_restore = QPushButton("♻ Restore File")
        self.btn_restore.setStyleSheet("background-color: #27ae60;")
        q_layout.addWidget(self.btn_quarantine)
        q_layout.addWidget(self.q_list)
        q_layout.addWidget(self.btn_restore)
        q_group.setLayout(q_layout)
        self.scan_layout.addWidget(q_group)
        self.pages.addWidget(self.page_scan)

        # --- PAGE 3: NETWORK (WIRETAP UPGRADE) ---
        self.page_net = QWidget()
        self.net_layout = QVBoxLayout(self.page_net)
        
        # Top Controls
        net_controls = QHBoxLayout()
        self.btn_net = QPushButton("Scan Connections")
        self.btn_lan = QPushButton("Scan LAN")
        self.btn_sniffer = QPushButton("🔴 Start Packet Sniffer")
        self.btn_sniffer.setStyleSheet("background-color: #c0392b; font-weight: bold;")
        
        net_controls.addWidget(self.btn_net)
        net_controls.addWidget(self.btn_lan)
        net_controls.addWidget(self.btn_sniffer)
        
        self.net_layout.addLayout(net_controls)

        # Splitter for Sniffer
        net_splitter = QSplitter(Qt.Vertical)
        
        # 1. Standard Output
        self.net_output = QTextEdit()
        self.net_output.setPlaceholderText("Scan Results (Connections/LAN)...")
        net_splitter.addWidget(self.net_output)
        
        # 2. Sniffer Output
        self.sniffer_output = QTextEdit()
        self.sniffer_output.setPlaceholderText("RAW PACKET DATA (Waiting to start...)\n")
        self.sniffer_output.setStyleSheet("background-color: #000; color: #00ff00; font-family: Consolas; font-size: 11px;")
        net_splitter.addWidget(self.sniffer_output)
        
        self.net_layout.addWidget(net_splitter)

        # Firewall Input
        fw_box = QHBoxLayout()
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("IP Address to Block")
        self.btn_block = QPushButton("⛔ BLOCK IP")
        self.btn_block.setObjectName("dangerBtn")
        fw_box.addWidget(self.ip_input)
        fw_box.addWidget(self.btn_block)
        self.net_layout.addLayout(fw_box)

        self.pages.addWidget(self.page_net)

        # --- PAGE 4: VAULT ---
        self.page_vault = QWidget()
        self.vault_layout = QVBoxLayout(self.page_vault)
        self.btn_encrypt = QPushButton("🔒 Encrypt File")
        self.btn_decrypt = QPushButton("🔓 Decrypt File")
        self.vault_output = QTextEdit()
        self.vault_layout.addWidget(self.btn_encrypt)
        self.vault_layout.addWidget(self.btn_decrypt)
        self.vault_layout.addWidget(self.vault_output)
        self.pages.addWidget(self.page_vault)

        # --- PAGE 5: IDENTITY ---
        self.page_id = QWidget()
        self.id_layout = QVBoxLayout(self.page_id)
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter email to check for breaches")
        self.btn_check_leak = QPushButton("Check Dark Web")
        self.id_output = QTextEdit()
        self.id_layout.addWidget(self.email_input)
        self.id_layout.addWidget(self.btn_check_leak)
        self.id_layout.addWidget(self.id_output)
        self.pages.addWidget(self.page_id)

        # --- PAGE 6: TOOLS ---
        self.page_tools = QWidget()
        self.tools_layout = QVBoxLayout(self.page_tools)
        self.btn_clean = QPushButton("🧹 Clean System Junk")
        self.tools_layout.addWidget(self.btn_clean)
        self.btn_shred = QPushButton("🗑 Secure File Shredder (Anti-Forensics)")
        self.btn_shred.setStyleSheet("background-color: #d35400;")
        self.tools_layout.addWidget(self.btn_shred)
        self.tools_layout.addSpacing(20)
        pass_layout = QHBoxLayout()
        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Enter password to test")
        self.pass_input.setEchoMode(QLineEdit.Password) 
        self.show_pass_chk = QCheckBox("Show")
        self.show_pass_chk.setStyleSheet("QCheckBox { color: #aaa; spacing: 5px; }")
        self.show_pass_chk.stateChanged.connect(lambda: self.pass_input.setEchoMode(QLineEdit.Normal if self.show_pass_chk.isChecked() else QLineEdit.Password))
        pass_layout.addWidget(self.pass_input)
        pass_layout.addWidget(self.show_pass_chk)
        self.tools_layout.addLayout(pass_layout)
        self.btn_check_pass = QPushButton("Test Strength")
        self.tools_layout.addWidget(self.btn_check_pass)
        self.tools_output = QTextEdit()
        self.tools_layout.addWidget(self.tools_output)
        self.pages.addWidget(self.page_tools)

        # --- PAGE 7: REPORTS ---
        self.page_report = QWidget()
        self.rep_layout = QVBoxLayout(self.page_report)
        self.btn_report = QPushButton("📄 Generate PDF Security Report")
        self.rep_layout.addWidget(self.btn_report)
        self.pages.addWidget(self.page_report)