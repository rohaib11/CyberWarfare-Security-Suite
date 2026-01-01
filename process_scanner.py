import psutil

def scan_processes():
    suspicious = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                p_info = proc.info
                # Logic: If a process uses >50% CPU, flag it
                if p_info['cpu_percent'] > 50:
                    suspicious.append(f"⚠ HIGH CPU [PID: {p_info['pid']}]: {p_info['name']} ({p_info['cpu_percent']}%)")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        return [f"Error scanning processes: {str(e)}"]
    
    return suspicious

def kill_process(pid):
    """Terminates a process by its PID."""
    try:
        proc = psutil.Process(pid)
        proc.terminate() # Try to stop gracefully
        return True, f"Process {pid} terminated successfully."
    except psutil.NoSuchProcess:
        return False, f"Process {pid} does not exist."
    except psutil.AccessDenied:
        return False, f"Access Denied! Run as Administrator to kill PID {pid}."
    except Exception as e:
        return False, f"Error: {str(e)}"