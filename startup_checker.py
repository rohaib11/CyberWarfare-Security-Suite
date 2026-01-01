import winreg

def check_startup():
    startup_items = []
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                startup_items.append(f"🚀 STARTUP: {name} -> {value}")
                i += 1
            except OSError:
                break
    except:
        pass
    return startup_items