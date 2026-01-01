import winreg
import time

def get_device_status(device_type):
    """
    Checks if Webcam or Microphone is currently in use.
    device_type: 'webcam' or 'microphone'
    """
    base_path = f"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\{device_type}"
    try:
        # Open the key where Windows stores app permissions
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_path)
        i = 0
        while True:
            try:
                # Iterate through apps (e.g., 'zoom.exe', 'chrome.exe')
                subkey_name = winreg.EnumKey(key, i)
                subkey = winreg.OpenKey(key, subkey_name)
                
                # Check 'LastUsedTimeStop'. If it is 0, it is currently running.
                try:
                    value, _ = winreg.QueryValueEx(subkey, "LastUsedTimeStop")
                    if value == 0:
                        return True, subkey_name # Return True and App Name
                except FileNotFoundError:
                    pass
                    
                i += 1
            except OSError:
                break # No more keys
    except Exception:
        pass
        
    return False, None

def check_privacy():
    cam_active, cam_app = get_device_status("webcam")
    mic_active, mic_app = get_device_status("microphone")
    
    status = []
    if cam_active:
        status.append(f"👁 CAM ACTIVE: {cam_app}")
    if mic_active:
        status.append(f"🎤 MIC ACTIVE: {mic_app}")
        
    return status