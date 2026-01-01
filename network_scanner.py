import psutil
import requests
import time
import subprocess
import socket

# Cache to avoid re-checking the same IP 100 times
ip_cache = {}

def get_ip_location(ip):
    """Asks an API where this IP is located."""
    if ip in ip_cache:
        return ip_cache[ip]
    
    if ip == "127.0.0.1" or ip.startswith("192.168") or ip.startswith("10."):
        return "Local Network"

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city", timeout=2)
        if response.status_code == 200:
            data = response.json()
            location = f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
            ip_cache[ip] = location
            return location
    except:
        return "Unknown Location"
    
    return "Unknown"

def scan_network():
    """Monitors active internet connections."""
    suspicious_traffic = []
    SAFE_PORTS = [80, 443, 53, 445] 
    
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections[:15]: 
            if conn.status == 'ESTABLISHED' and conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                pid = conn.pid
                
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name()
                except:
                    proc_name = "Unknown"

                if remote_port not in SAFE_PORTS:
                    loc = get_ip_location(remote_ip)
                    suspicious_traffic.append(f"📡 {proc_name} -> {remote_ip} ({loc})")
                    
    except Exception:
        pass
        
    if not suspicious_traffic:
        suspicious_traffic.append("No suspicious traffic on non-standard ports.")

    return suspicious_traffic

def scan_lan_devices():
    """Uses ARP table to find other devices on the network."""
    devices = []
    try:
        output = subprocess.check_output("arp -a", shell=True).decode()
        
        for line in output.split('\n'):
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[0]
                mac = parts[1]
                type_ = parts[2]
                
                if ip.startswith("192.168") or ip.startswith("10."):
                     devices.append(f"🖥 DEVICE: {ip}  |  MAC: {mac}  |  Type: {type_}")
                     
    except Exception as e:
        devices.append(f"Error scanning LAN: {str(e)}")
        
    if not devices:
        devices.append("No other devices found (or ARP cache empty). Ping some devices first!")
        
    return devices

# --- THIS IS THE FUNCTION THAT WAS MISSING ---
def set_internet_state(enable=True):
    """
    Enables or Disables the Wi-Fi/Ethernet Adapter (Kill Switch).
    REQUIRES ADMIN RIGHTS.
    """
    state = "enable" if enable else "disable"
    # This command tries both common interface names
    cmd_wifi = f'netsh interface set interface "Wi-Fi" admin={state}'
    cmd_eth = f'netsh interface set interface "Ethernet" admin={state}'
    
    try:
        # Run silently
        subprocess.run(cmd_wifi, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(cmd_eth, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        
        if enable:
            return "✅ Internet Restored."
        else:
            return "⛔ PANIC: Internet connection CUT."
    except Exception as e:
        return f"Error changing network state: {e}"