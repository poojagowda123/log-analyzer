import psutil
import time
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(
    filename='process_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Known dangerous processes or signatures (Simple Demo List)
# In production, use hashes or more complex heuristics.
SUSPICIOUS_NAMES = [
    "nc.exe", "ncat.exe", "netcat.exe", 
    "mimikatz.exe", "pwdump.exe", 
    "keylogger.exe", "malware.exe"
]

class ProcessMonitor:
    def __init__(self):
        self.running = False

    def check_processes(self):
        """Scans running processes for suspicious activity."""
        detections = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                p_info = proc.info
                name = p_info['name'].lower() if p_info['name'] else ""
                
                # 1. Name Check
                if name in SUSPICIOUS_NAMES:
                    detections.append(p_info)
                    logging.warning(f"Suspicious Process Found: {name} (PID: {p_info['pid']})")
                    continue
                
                # 2. Command Line Heuristics
                # e.g., PowerShell encoded commands
                cmd = p_info['cmdline'] or []
                cmd_str = " ".join(cmd).lower()
                
                if "powershell" in name and ("-enc" in cmd_str or "-encodedcommand" in cmd_str):
                    # Only flag if it's super long (heuristic)
                    if len(cmd_str) > 500: 
                        detections.append(p_info)
                        logging.warning(f"Suspicious PowerShell Detected: PID {p_info['pid']}")
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        return detections

    def kill_process(self, pid):
        """Terminates a process by PID."""
        try:
            p = psutil.Process(pid)
            p.terminate()
            p.wait(timeout=3)
            logging.info(f"Successfully terminated subprocess {pid}")
            print(f"🔫 KILLED Process {pid}")
            return True
        except Exception as e:
            logging.error(f"Failed to kill process {pid}: {e}")
            print(f"❌ Failed to kill {pid}: {e}")
            return False

    def monitor_loop(self, interval=5):
        """Continuous monitoring loop."""
        self.running = True
        print(f"Process Monitor Active (Scan Interval: {interval}s)...")
        
        while self.running:
            bad_procs = self.check_processes()
            for proc in bad_procs:
                print(f"🚨 DETECTED SUSPICIOUS PROCESS: {proc['name']} (PID: {proc['pid']})")
                # Auto-kill for demo purposes? Or callback?
                # For now, we just report.
            
            time.sleep(interval)

if __name__ == "__main__":
    pm = ProcessMonitor()
    # pm.monitor_loop()
