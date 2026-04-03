
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta
import random

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "Output"
OUTPUT_DIR.mkdir(exist_ok=True)
ML_OUTPUT = OUTPUT_DIR / "ml_anomalies.csv"
ATTACK_OUTPUT = OUTPUT_DIR / "attack_identifications.csv"
SUSPICIOUS_OUTPUT = OUTPUT_DIR / "suspicious_events.csv"

class DemoInjector:
    def __init__(self):
        self.output_file = ML_OUTPUT
        self.attack_file = ATTACK_OUTPUT
        self.suspicious_file = SUSPICIOUS_OUTPUT
        self.anomalies = [] # In-memory list to append to
        
    def _save(self, new_anomaly):
        # Load existing or create new
        if self.output_file.exists():
            df = pd.read_csv(self.output_file)
        else:
            df = pd.DataFrame(columns=["timestamp","event_id","source","username","ip","anomaly_name","severity","identified_attack","ml_score","failed_count","message","attack_confidence"])
            
        # Append
        df = pd.concat([df, pd.DataFrame([new_anomaly])], ignore_index=True)
        # Sort by timestamp desc
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp', ascending=False)
        
        df.to_csv(self.output_file, index=False)
        
        # Also update attack file
        if self.attack_file.exists():
            df_atk = pd.read_csv(self.attack_file)
        else:
            # ensure attack confidence is present
            if "attack_confidence" not in new_anomaly: new_anomaly["attack_confidence"] = 0.95
            df_atk = pd.DataFrame(columns=df.columns)
            
        df_atk = pd.concat([df_atk, pd.DataFrame([new_anomaly])], ignore_index=True)
        df_atk.to_csv(self.attack_file, index=False)
        
        # Also update Suspicious Events (Page 2)
        if self.suspicious_file.exists():
            df_susp = pd.read_csv(self.suspicious_file)
        else:
            df_susp = pd.DataFrame(columns=["type","username","failed_attempts","timestamp","count","ip","severity","description"])
            
        susp_row = {
            "type": new_anomaly['identified_attack'], # Map to 'type'
            "username": new_anomaly['username'],
            "failed_attempts": new_anomaly['failed_count'] if new_anomaly['failed_count'] > 0 else None,
            "timestamp": new_anomaly['timestamp'],
            "count": new_anomaly['failed_count'] if new_anomaly['failed_count'] > 0 else 1,
            "ip": new_anomaly['ip'],
            "severity": new_anomaly['severity'],
            "description": new_anomaly['message']
        }
        
        df_susp = pd.concat([df_susp, pd.DataFrame([susp_row])], ignore_index=True)
        df_susp['timestamp'] = pd.to_datetime(df_susp['timestamp'])
        df_susp = df_susp.sort_values('timestamp', ascending=False)
        df_susp.to_csv(self.suspicious_file, index=False)
        
        print(f"✅ Injected: {new_anomaly['anomaly_name']}")

    def clear_data(self):
        if self.output_file.exists(): self.output_file.unlink()
        if self.attack_file.exists(): self.attack_file.unlink()
        if self.suspicious_file.exists(): self.suspicious_file.unlink()
        
        # Create empty with headers
        pd.DataFrame(columns=["timestamp","event_id","source","username","ip","anomaly_name","severity","identified_attack","ml_score","failed_count","message","attack_confidence"]).to_csv(self.output_file, index=False)
        pd.DataFrame(columns=["type","username","failed_attempts","timestamp","count","ip","severity","description"]).to_csv(self.suspicious_file, index=False)
        print("🧹 Data Cleared")

    def inject_brute_force(self):
        self._save({
            "timestamp": datetime.now(),
            "event_id": 4625,
            "source": "windows",
            "username": "admin_user",
            "ip": "192.168.1.105",
            "anomaly_name": "Brute Force Attack (15 Failed Attempts)",
            "severity": "HIGH",
            "identified_attack": "Brute Force",
            "ml_score": -0.95,
            "failed_count": 15,
            "attack_confidence": 0.99,
            "message": "Account: admin_user failed to log on. Count: 15. Source: 192.168.1.105"
        })

    def inject_privilege_escalation(self):
        self._save({
            "timestamp": datetime.now(),
            "event_id": 4672,
            "source": "windows",
            "username": "SYSTEM_SERVICE",
            "ip": "Internal",
            "anomaly_name": "Privilege Escalation (Admin Assigned)",
            "severity": "HIGH",
            "identified_attack": "Privilege Escalation",
            "ml_score": -0.80,
            "failed_count": 0,
            "attack_confidence": 0.88,
            "message": "Special privileges assigned to new logon."
        })

    def inject_bad_usb(self):
        self._save({
            "timestamp": datetime.now(),
            "event_id": 2003,
            "source": "usb",
            "username": "Unknown",
            "ip": "Unknown",
            "anomaly_name": "Suspicious USB (Rubber Ducky Type)",
            "severity": "HIGH",
            "identified_attack": "BadUSB",
            "ml_score": -0.91,
            "failed_count": 0,
            "attack_confidence": 0.95,
            "message": "USB Device Connected: O.MG Cable (VID_046D&PID_C31C)"
        })

    def inject_exfiltration(self):
        self._save({
            "timestamp": datetime.now(),
            "event_id": 4663,
            "source": "windows",
            "username": "intern_john",
            "ip": "10.0.0.55",
            "anomaly_name": "Data Exfiltration (Sensitive File Access)",
            "severity": "MEDIUM",
            "identified_attack": "Exfiltration",
            "ml_score": -0.65,
            "failed_count": 0,
            "attack_confidence": 0.75,
            "message": "Access Object: C:\\Confidential\\Salaries_2026.xlsx"
        })

    def inject_lateral_movement(self):
        self._save({
            "timestamp": datetime.now(),
            "event_id": 4624,
            "source": "windows",
            "username": "hr_manager",
            "ip": "192.168.1.105", 
            "anomaly_name": "Lateral Movement (IP Reuse)",
            "severity": "HIGH",
            "identified_attack": "Lateral Movement",
            "ml_score": -0.88,
            "failed_count": 0,
            "attack_confidence": 0.82,
            "message": "Logon from Suspicious IP (192.168.1.105) Linked to multiple accounts"
        })
        
    def inject_after_hours(self):
        self._save({
            "timestamp": datetime.now() - timedelta(hours=14), 
            "event_id": 4624,
            "source": "windows",
            "username": "maintenance_act",
            "ip": "192.168.1.200",
            "anomaly_name": "Unusual After-Hours Activity (3:00 AM)",
            "severity": "MEDIUM",
            "identified_attack": "Anomalous Login",
            "ml_score": -0.55,
            "failed_count": 0,
            "attack_confidence": 0.60,
            "message": "Successful Logon during non-business hours."
        })

    def inject_ransomware(self):
        self._save({
            "timestamp": datetime.now(), 
            "event_id": 4663,
            "source": "windows",
            "username": "compromised_user",
            "ip": "10.0.0.12",
            "anomaly_name": "Ransomware Behavior (Mass File Modification)",
            "severity": "CRITICAL",
            "identified_attack": "Ransomware",
            "ml_score": -0.99,
            "failed_count": 0,
            "attack_confidence": 0.98,
            "message": "Mass write access detected: 500+ files renamed with .crypt extension in /Finance."
        })

    def inject_persistence(self):
        self._save({
            "timestamp": datetime.now(), 
            "event_id": 4698,
            "source": "windows",
            "username": "SYSTEM",
            "ip": "Internal",
            "anomaly_name": "Persistence Mechanism (Scheduled Task)",
            "severity": "HIGH",
            "identified_attack": "Persistence",
            "ml_score": -0.85,
            "failed_count": 0,
            "attack_confidence": 0.92,
            "message": "Suspicious Task Created: 'Updater_v2.exe' inAppData/Temp folder."
        })

    def inject_password_spray(self):
        self._save({
            "timestamp": datetime.now(), 
            "event_id": 4625,
            "source": "windows",
            "username": "MULTIPLE_ACCOUNTS",
            "ip": "45.33.32.156",
            "anomaly_name": "Password Spraying (Failed Logins)",
            "severity": "HIGH",
            "identified_attack": "Password Spray",
            "ml_score": -0.89,
            "failed_count": 20,
            "attack_confidence": 0.94,
            "message": "Failed Logons for 5 different accounts from single external IP."
        })

    def inject_user_creation(self):
        self._save({
            "timestamp": datetime.now(), 
            "event_id": 4720,
            "source": "windows",
            "username": "Admin_User",
            "ip": "Internal",
            "anomaly_name": "Suspicious Account Creation (Backdoor)",
            "severity": "HIGH",
            "identified_attack": "Persistence",
            "ml_score": -0.82,
            "failed_count": 0,
            "attack_confidence": 0.90,
            "message": "A user account was created. Subject: Admin_User. Target: 'sys_backup'."
        })

    def inject_log_clearing(self):
        self._save({
            "timestamp": datetime.now(), 
            "event_id": 1102,
            "source": "windows",
            "username": "Administrator",
            "ip": "Internal",
            "anomaly_name": "Security Log Cleared (Covering Tracks)",
            "severity": "CRITICAL",
            "identified_attack": "Defense Evasion",
            "ml_score": -0.98,
            "failed_count": 0,
            "attack_confidence": 0.99,
            "message": "The audit log was cleared. Attempt to hide activity detected."
        })

    def inject_late_night(self):
        # Force a time between 12 AM and 5 AM
        # Example: 02:33 AM
        t = datetime.now().replace(hour=2, minute=33, second=15)
        if t > datetime.now():
            t = t - timedelta(days=1) # Make it last night if 2 AM hasn't happened yet today

        self._save({
            "timestamp": t,
            "event_id": 4624,
            "source": "windows",
            "username": "night_shift_user",
            "ip": "192.168.1.110",
            "anomaly_name": "Late Night Access (02:33 AM)",
            "severity": "MEDIUM",
            "identified_attack": "Anomalous Login",
            "ml_score": -0.65,
            "failed_count": 0,
            "attack_confidence": 0.75,
            "message": "Successful Logon detected well outside business hours (02:33 AM)."
        })

if __name__ == "__main__":
    # If run as script, just generate all (Legacy mode)
    injector = DemoInjector()
    injector.clear_data()
    injector.inject_brute_force()
    injector.inject_privilege_escalation()
    injector.inject_bad_usb()
    injector.inject_exfiltration()
    injector.inject_lateral_movement()
    injector.inject_after_hours()
