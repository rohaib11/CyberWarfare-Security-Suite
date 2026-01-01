# 🛡️ Cyber Warfare Security Suite (v5.0)

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge\&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge\&logo=windows)
![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**An advanced, military-grade cybersecurity monitoring and defense platform built with Python.**
This suite combines AI-driven anomaly detection, active network forensics, and zero-trust lockdown mechanisms to transform a standard PC into a secure fortress.

---

## 🚀 Key Features

### ⚔️ Active Defense Engines

* **🏰 Fortress Mode (Zero-Trust):** Instantly snapshots running processes and aggressively kills *any* new application that tries to start. Perfect for leaving your PC unattended.
* **🚨 Network Kill Switch:** A physical "Panic Button" that instantly disables all network adapters (Wi-Fi/Ethernet) via Admin API during a suspected breach.
* **🔌 USB Sentinel:** Automatically detects inserted USB drives and scans them for malicious `autorun.inf` or dangerous executables before they can execute.

### 🧠 Intelligence & Detection

* **🤖 AI Anomaly Brain:** Uses `IsolationForest` (Machine Learning) to learn your PC's normal CPU/RAM/Disk usage patterns and flags deviations in real-time.
* **🧬 YARA Pattern Matching:** Scans files against a database of malware rules to detect hidden threats that bypass standard AVs.
* **☁️ Cloud Forensics:** Calculates file hashes (SHA-256) and checks them against the **VirusTotal API** database.

### 📉 Network Warfare (SIEM)

* **📡 Packet Sniffer (Wiretap):** Captures raw TCP/UDP packets in real-time to detect data exfiltration or cleartext HTTP traffic.
* **🛡️ Brute Force Monitor:** Hooks into Windows Event Logs (EventID 4625) to detect and alert on repeated failed login attempts.
* **🔎 LAN Scanner:** Maps your local network using ARP to identify all connected devices (Phones, IoT, unauthorized users).

### 🕵️ Privacy & Forensics

* **👁️ Spyware Hunter:** Monitors the Windows Registry to detect if any application is secretly accessing your **Webcam** or **Microphone**.
* **🗑️ Secure File Shredder:** Overwrites files with random garbage data (3 passes) before deletion, making forensic recovery impossible.
* **🔒 Secure Vault:** AES-256 encryption module to lock sensitive files with a password.

---

## 📸 Screenshots


```text
screenshots/
├── dashboard.png
├── process_scan.png
├── network_monitor.png
├── fortress_mode.png
└── alerts.png
```

<img width="1267" height="892" alt="image" src="https://github.com/user-attachments/assets/4d35c630-c7fa-4b25-8fc9-40ccc041271d" />

<img width="1280" height="902" alt="image" src="https://github.com/user-attachments/assets/1d50dc0e-790a-4a62-9572-8194cd1537f8" />

<img width="1280" height="895" alt="image" src="https://github.com/user-attachments/assets/73041a14-81f4-42ac-a605-1f8ad27728dc" />

<img width="1265" height="886" alt="image" src="https://github.com/user-attachments/assets/de4fd0f9-66fa-4dc8-8588-19431eb266ea" />

<img width="1276" height="885" alt="image" src="https://github.com/user-attachments/assets/5ce5276c-a96b-4f91-bf52-8352533fd0b1" />


## 🛠️ Installation

### Prerequisites

* Python 3.8+
* Windows 10/11 (Admin Rights required for Sniffer & Kill Switch)
* [Npcap](https://npcap.com/) (Required for Packet Sniffer)

### 1. Clone the Repository

```bash
git clone https://github.com/rohaib11/CyberWarfare-Security-Suite.git
cd CyberWarfare-Security-Suite
```

### 2. Set Up Virtual Environment

```bash
python -m venv venv
# Activate the environment
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

> **Note:** If you encounter errors with `pywin32`, run:
> `python venv/Scripts/pywin32_postinstall.py -install`

---

## 🖥️ Usage

Run the main application as Administrator (required for network & process control):

```bash
python main.py
```

### Dashboard Controls

* **Toggle Real-Time Protection:** Enables the AI Monitor and Ransomware Guard.
* **Fortress Mode:** Locks the system to current processes only.
* **Panic Button:** Cuts internet connection immediately.

---

## 🔧 Generating an Executable (.exe)

To build a standalone portable file:

```bash
pyinstaller --noconsole --onefile --uac-admin --icon="shield.ico" --name "CyberWarfare_Suite" main.py
```

---

## 🧩 Tech Stack

| Component        | Technology                      |
| ---------------- | ------------------------------- |
| GUI Framework    | PyQt5 (Modern Dark Theme)       |
| Machine Learning | Scikit-Learn (Isolation Forest) |
| Network Analysis | Scapy, Socket                   |
| System Control   | Psutil, PyWin32, Subprocess     |
| Cryptography     | Cryptography (Fernet AES)       |
| Forensics        | YARA-Python, WinReg             |

---

## ⚠️ Disclaimer

This software is for **educational and defensive purposes only**.
The "Kill Switch," "Packet Sniffer," and "Lockdown" features are powerful tools.
The developer is not responsible for any damage caused by misuse or accidental system lockouts.
Always test in a **safe environment first**.

---

## 📜 License

Distributed under the **MIT License**. See LICENSE for more information.

**Built by Muhammad Rohaib** → Protecting Systems, One Line of Code at a Time.""
