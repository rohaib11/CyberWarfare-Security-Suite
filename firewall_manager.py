import subprocess

def block_ip_address(ip_address):
    """Uses Windows Firewall to block an IP."""
    rule_name = f"Block_IP_{ip_address}"
    
    # Command to add a firewall rule
    command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
    
    try:
        # Run command hidden
        subprocess.run(command, shell=True, check=True)
        return True, f"🚫 IP {ip_address} has been BLOCKED successfully."
    except subprocess.CalledProcessError:
        return False, "❌ Failed. Run App as Administrator!"

def unblock_ip_address(ip_address):
    rule_name = f"Block_IP_{ip_address}"
    command = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    
    try:
        subprocess.run(command, shell=True, check=True)
        return True, f"✅ IP {ip_address} UNBLOCKED."
    except:
        return False, "❌ Failed to unblock."