import win32evtlog
import pandas as pd
import numpy as np
import re
from pathlib import Path
import joblib
from datetime import datetime
import time 

import os
import math
import subprocess
from sklearn.ensemble import IsolationForest
from active_response import ActiveResponseModule

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT = BASE_DIR / "Output"
OUTPUT.mkdir(exist_ok=True)
MODEL_DIR = OUTPUT / "models"

# --------------------------------------------------------------------------
# INTEGRATED USB SCANNER (Merged from scan_usb_drive.py)
# --------------------------------------------------------------------------
SCAN_OUTPUT = BASE_DIR / "Output" / "usb_file_scan.csv"
SUSPICIOUS_EXTS = ['.exe', '.bat', '.scr', '.vbs', '.ps1', '.cmd', '.dll']

def get_drive_list():
    """Detect removable drives and external HDDs using WMIC."""
    drives = []
    try:
        # Run wmic command to get ALL logical disks (Type 2=Removable, 3=Local)
        # We need Type 3 because some USB sticks show as Local Disk
        result = subprocess.check_output(['wmic', 'logicaldisk', 'where', 'drivetype=2 or drivetype=3', 'get', 'deviceid'], shell=True)
        output = result.decode('utf-8', errors='ignore')
        
        # Parse output
        for line in output.splitlines():
            line = line.strip()
            if line and ":" in line and "DeviceID" not in line:
                # FILTER: Exclude System Drive (C:) and Project Drive (D:) called 'LogAnalyzer1'
                # Modify this list if you have other fixed drives to ignore
                if line.upper() in ["C:", "D:"]:
                    continue
                drives.append(line)
        
        if not drives:
             print("Debug: No external drives found (Checked Type 2 & 3, excluded C:/D:)")
             
    except Exception as e:
        print(f"Error detecting drives: {e}")
    return drives

def calculate_entropy(filepath):
    """Calculate Shannon Entropy of file content (0-8). Higher > Packed/Encrypted."""
    try:
        with open(filepath, 'rb') as f:
            data = f.read(4096) # Read first 4KB for speed
            if not data: return 0
            
            entropy = 0
            for x in range(256):
                p_x = float(data.count(x))/len(data)
                if p_x > 0:
                    entropy += - p_x * math.log(p_x, 2)
            return entropy
    except:
        return 0

def scan_drive(drive_letter):
    print(f"Scanning Drive: {drive_letter}")
    files_data = []
    
    try:
        # Walk the drive
        for root, dirs, files in os.walk(drive_letter + "\\"):
            for file in files:
                filepath = os.path.join(root, file)
                size = 0
                try: size = os.path.getsize(filepath)
                except: pass
                
                ext = os.path.splitext(file)[1].lower()
                
                # Heuristic Features
                is_suspicious_ext = 1 if ext in SUSPICIOUS_EXTS else 0
                has_double_ext = 1 if file.count('.') > 1 and ext in SUSPICIOUS_EXTS else 0
                
                # Entropy (only calc if suspicious or executable to save time)
                entropy = 0
                if is_suspicious_ext or ext in ['.pdf', '.docx']:
                     entropy = calculate_entropy(filepath)
                
                files_data.append({
                    'filename': file,
                    'path': filepath,
                    'extension': ext,
                    'size_kb': size / 1024,
                    'entropy': entropy,
                    'is_suspicious_ext': is_suspicious_ext,
                    'has_double_ext': has_double_ext
                })
    except Exception as e:
        print(f"Error scanning {drive_letter}: {e}")
            
    return pd.DataFrame(files_data)

def classify_files(df):
    if df.empty: return df
    
    # Features for ML
    features = df[['entropy', 'is_suspicious_ext', 'has_double_ext', 'size_kb']].fillna(0)
    
    # Train quick Isolation Forest on this batch (detecting outliers within the drive)
    iso = IsolationForest(contamination=0.1, random_state=42)
    df['anomaly_score'] = iso.fit_predict(features) # -1 = Anomaly
    
    # Verdict Logic
    def get_verdict_and_reason(row):
        score = 0
        reasons = []
        
        if row['is_suspicious_ext']: 
            score += 50
            reasons.append("Suspicious Extension")
            
        if row['has_double_ext']: 
            score += 80
            reasons.append("Double Extension (Masquerading)")
            
        if row['entropy'] > 7.0: 
            score += 30
            reasons.append("High Entropy (Packed/Encrypted)")
            
        if row['anomaly_score'] == -1: 
            score += 20
            reasons.append("Statistical Anomaly")
            
        verdict = "SAFE"
        if score > 50: verdict = "MALICIOUS"
        elif score > 20: verdict = "SUSPICIOUS"
        
        if verdict == "SAFE":
            return pd.Series([verdict, "Clean"])
        else:
            return pd.Series([verdict, ", ".join(reasons)])
        
    df[['verdict', 'reason']] = df.apply(get_verdict_and_reason, axis=1)
    df['risk_score'] = df['entropy'] * 10 + (df['is_suspicious_ext'] * 50)
    
    return df

def scan_all_drives():
    """Scans all connected removable drives and saves report."""
    # STRICT CLEANUP: Remove old scan results immediately
    if SCAN_OUTPUT.exists():
        try:
            os.remove(SCAN_OUTPUT)
            print(f"Cleared previous scan results: {SCAN_OUTPUT}")
        except Exception as e:
            print(f"Warning: Could not clear old scan file: {e}")

    drives = get_drive_list()
    
    # Initialize empty result structure
    final_df = pd.DataFrame(columns=['filename','path','verdict','risk_score', 'extension', 'size_kb', 'entropy', 'is_suspicious_ext', 'has_double_ext', 'anomaly_score'])

    if not drives:
        print("No Removable Drives Detected.")
        final_df.to_csv(SCAN_OUTPUT, index=False)
        return False
    else:
        all_files = []
        for d in drives:
            print(f"Found Removable Drive: {d}")
            df = scan_drive(d)
            if not df.empty:
                df = classify_files(df)
                all_files.append(df)
        
        if all_files:
            final_df = pd.concat(all_files)
            print(f"Content Scan Complete. {len(final_df)} files found.")
        else:
            print("No files found on connected drives.")
            
        # ALWAYS write the result (even if empty, to confirm 'real-time' state is empty)
        final_df.to_csv(SCAN_OUTPUT, index=False)
        print(f"Results saved to {SCAN_OUTPUT}")
        return True

SCANNER_AVAILABLE = True

# Global debounce timer
LAST_SCAN_TIME = 0

USB_LOG_FILE = OUTPUT / "usb_logs_parsed.csv"
USB_SUSPICIOUS_FILE = OUTPUT / "usb_suspicious_events.csv"

# Load ML Models if available
try:
    usb_model = joblib.load(MODEL_DIR / "usb_malware_model.joblib")
    usb_encoder = joblib.load(MODEL_DIR / "usb_encoders.joblib")
    ML_AVAILABLE = True
except:
    print("Warning: ML model not found. Running in heuristic mode only.")
    ML_AVAILABLE = False

# Event IDs related to USB activity
USB_EVENTS = {
    2003: "USB Device Connected",
    2100: "USB Device Removed",
    1006: "USB Device Error",
    400:  "Device Enumeration Started"
}

def predict_malicious(vendor_id, timestamp):
    if not ML_AVAILABLE:
        return 0, 0.0
    
    try:
        hour = timestamp.hour
        is_weekend = 1 if timestamp.weekday() >= 5 else 0
        
        # approximate duration (placeholder as we can't easily track duration in real-time stream without state)
        # For prediction we'll assume a short duration to be safe/pessimistic or average
        duration = 300 
        
        # Handle unknown vendor
        try:
            vendor_encoded = usb_encoder.transform([str(vendor_id)])[0]
        except:
            # Fallback for unknown vendor - treat as "suspicious" or map to a known "others" category if trained
            # Here we map to the first class just to avoid crash, but ideally should be separate
            vendor_encoded = 0 
            
        features = pd.DataFrame([{
            'vendor_encoded': vendor_encoded,
            'hour': hour,
            'duration_seconds': duration,
            'is_weekend': is_weekend
        }])
        
        is_malicious = usb_model.predict(features)[0]
        confidence = np.max(usb_model.predict_proba(features))
        
        return is_malicious, confidence
    except Exception as e:
        print(f"ML Prediction Error: {e}")
        return 0, 0.0

def to_naive(dt):
    """Safely convert any datetime to offset-naive."""
    if dt is None: return datetime.now()
    if hasattr(dt, 'tzinfo') and dt.tzinfo is not None:
        return dt.replace(tzinfo=None)
    return dt

def read_system_pnp_logs():
    """Fallback: Read standard System log for Plug and Play events (Kernel-PnP)."""
    logs = []
    suspicious_events = []
    server = 'localhost'
    
    try:
        handle = win32evtlog.OpenEventLog(server, "System")
    except Exception as e:
        print(f"Error opening System log: {e}")
        return [], []

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    print(f"DEBUG: Scanning System Log for PnP events...")
    count_scanned = 0
    total_checked = 0
    MAX_CHECK = 3000 # Stop after checking this many total events
    
    while True:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        if not events:
            break

        for event in events:
            total_checked += 1
            if total_checked > MAX_CHECK:
                break
                
            if event.SourceName == "Microsoft-Windows-Kernel-PnP":
                count_scanned += 1
                # Debug print for first few events
                if count_scanned <= 5:
                    print(f"DEBUG: Found PnP Event ID={event.EventID}")
                    try:
                        print(f"DEBUG: Msg={event.StringInserts}")
                    except: pass
                
            if event.SourceName != "Microsoft-Windows-Kernel-PnP":
                continue
                
            # TIME FILTER & SANITIZATION
            try:
                raw_time = event.TimeGenerated
                if hasattr(raw_time, 'tzinfo') and raw_time.tzinfo is not None:
                     event_time = raw_time.replace(tzinfo=None)
                else:
                     event_time = raw_time
                
                # STRICT FILTER: Current Year Only
                if event_time.year < datetime.now().year:
                    continue

                if (datetime.now() - event_time).days > 30:
                    continue
            except Exception as e:
                continue

            # Event 400/410/433 are common, but let's be more permissive if we see "USB"
            # We will scan deeper (up to 500 PnP events) to find the USB insertion
            if count_scanned > 500: break
            
            try:
                full_msg = str(event.StringInserts)
            except:
                full_msg = ""

            # Check for USB keyword aggressively
            # Note: 219 is usually "Driver failed to load", we skip that unless it says USB
            if "USB" not in full_msg and "VID_" not in full_msg:
                continue
                
            # If we found a USB event, print it!
            # print(f"DEBUG: Found USB Candidate! ID={event.EventID}")

            # Parse VID/PID
            vendor = "Unknown"
            product = "Unknown"
            vid_match = re.search(r"VID_([0-9A-F]+)", full_msg, re.IGNORECASE)
            pid_match = re.search(r"PID_([0-9A-F]+)", full_msg, re.IGNORECASE)

            if vid_match: vendor = vid_match.group(1).upper()
            if pid_match: product = pid_match.group(1).upper()
            
            summary = f"USB Device Configured: Vendor {vendor} Product {product}"
            
            # Check Malicious
            is_malicious = 0
            confidence = 0.0
            if vendor != "Unknown":
                is_malicious, confidence = predict_malicious(vendor, event_time)
                if is_malicious == 1:
                    suspicious_events.append({
                        "timestamp": event_time,
                        "vendor_id": vendor,
                        "product_id": product,
                        "reason": f"ML Model Detection (Confidence: {confidence:.2f})",
                        "status": "Flagged"
                    })

            # INTEGRATION: Trigger Content Scan
            # DEBOUNCE: Only scan max once every 30 seconds to avoid loop on historical events
            global LAST_SCAN_TIME
            if SCANNER_AVAILABLE and (time.time() - LAST_SCAN_TIME > 30):
                print("DEBUG: Triggering Auto-Content Scan (PnP)...")
                try:
                    if scan_all_drives():
                        LAST_SCAN_TIME = time.time()
                except Exception as e:
                    print(f"Auto-scan failed: {e}")

            logs.append({
                "timestamp": event_time,
                "event_id": event.EventID,
                "event_type": "PnP Device Configured",
                "vendor_id": vendor,
                "product_id": product,
                "raw_message": full_msg,
                "activity_summary": summary,
                "is_malicious": is_malicious,
                "risk_score": confidence if is_malicious else 0
            })

    return logs, suspicious_events


def read_usb_logs():
    # 1. Try DriverFrameworks (Best for USB specific)
    logs, susp = [], []
    
    server = 'localhost'
    log_type = "Microsoft-Windows-DriverFrameworks-UserMode/Operational"

    try:
        handle = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        total_checked = 0
        MAX_CHECK = 3000
        
        while True:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events: break
            
            for event in events:
                total_checked += 1
                if total_checked > MAX_CHECK: break
                
                if event.EventID not in USB_EVENTS: continue

                # TIME FILTER & SANITIZATION
                try:
                    raw_time = event.TimeGenerated
                    # FORCE NAIVE
                    if hasattr(raw_time, 'tzinfo') and raw_time.tzinfo is not None:
                         event_time = raw_time.replace(tzinfo=None)
                    else:
                         event_time = raw_time
                    
                    # STRICT FILTER for DEMO: Only show events from CURRENT YEAR (2026)
                    # This eliminates the persistent 2025 alerts
                    if event_time.year < datetime.now().year:
                        continue
                        
                    # Also keep the 30-day buffer just in case
                    if (datetime.now() - event_time).days > 30:
                        continue
                except Exception as e:
                    continue
                
                message = str(event.StringInserts)
                vendor = "Unknown"
                product = "Unknown"
                vid_match = re.search(r"VID_([0-9A-F]+)", message)
                pid_match = re.search(r"PID_([0-9A-F]+)", message)
                if vid_match: vendor = vid_match.group(1)
                if pid_match: product = pid_match.group(1)
                
                event_desc = USB_EVENTS.get(event.EventID, "Unknown Event")
                if vendor != "Unknown": summary = f"{event_desc}: Vendor {vendor} Product {product}"
                else: summary = f"{event_desc}: Generic Device"

                is_malicious = 0
                confidence = 0.0
                if event.EventID == 2003:
                    is_malicious, confidence = predict_malicious(vendor, event_time)
                    if is_malicious == 1:
                        susp.append({
                            "timestamp": event_time, "vendor_id": vendor, "product_id": product,
                            "reason": f"ML Model Detection (Confidence: {confidence:.2f})", "status": "Flagged"
                        })

                logs.append({
                    "timestamp": event_time, "event_id": event.EventID, "event_type": event_desc,
                    "vendor_id": vendor, "product_id": product, "raw_message": message, "activity_summary": summary,
                    "is_malicious": is_malicious, "risk_score": confidence if is_malicious else 0
                })
    except Exception as e:
        print(f"Note: DriverFrameworks log not accessible ({e}). Falling back to System/PnP.")

    # 2. Merge with System PnP Logs (Fallback/Supplement)
    pnp_logs, pnp_susp = read_system_pnp_logs()
    
    # Merge and Sort
    all_logs = logs + pnp_logs
    all_susp = susp + pnp_susp
    
    # Sort by timestamp descending
    all_logs.sort(key=lambda x: x['timestamp'], reverse=True)
    all_susp.sort(key=lambda x: x['timestamp'], reverse=True)

    return all_logs, all_susp


def save_usb_logs():
    # SCORCHED EARTH: Force delete old artifacts to remove stale 2025 data
    try:
        if USB_SUSPICIOUS_FILE.exists():
            os.remove(USB_SUSPICIOUS_FILE)
            print("Cleaning up old suspicious events file...")
    except: pass

    data, suspicious = read_usb_logs()

    if not data:
        print("No USB events found.")
    else:
        df = pd.DataFrame(data)
        
        # ---------------------------------------------------------
        # ANALYSIS ALIGNMENT (User Request)
        # ---------------------------------------------------------
        # 1. Unify Column Names with Windows Logs
        if 'risk_score' in df.columns:
            df.rename(columns={'risk_score': 'threat_score', 'is_malicious': 'is_threat'}, inplace=True)
            
        # Ensure common columns exist
        if 'ip' not in df.columns:
            df['ip'] = 'Local Device' 
        if 'source' not in df.columns:
            df['source'] = 'usb'

        # 2. MITRE ATT&CK Mapping (Same as Windows)
        try:
            from mitre_mapping import MITRE_MAPPING
            print("Mapping USB events to MITRE ATT&CK Framework...")
            
            def get_mitre_tag(eid):
                if eid in MITRE_MAPPING:
                    m = MITRE_MAPPING[eid]
                    return f"{m['technique_id']} - {m['technique_name']}"
                return ""
                
            def get_mitre_tactic(eid):
                if eid in MITRE_MAPPING:
                    return MITRE_MAPPING[eid]['tactic']
                return ""

            df['mitre_technique'] = df['event_id'].apply(get_mitre_tag)
            df['mitre_tactic'] = df['event_id'].apply(get_mitre_tactic)
        except ImportError:
            pass

        # ---------------------------------------------------------

        # ---------------------------------------------------------
        # ADVANCED CONTEXTUAL THREAT ANALYSIS (User Request)
        # ---------------------------------------------------------
        try:
            print("Running Advanced Contextual Threat Analysis...")
            threats = []
            
            # 1. LOAD WINDOWS LOGS FOR CORRELATION
            win_log_path = BASE_DIR / "Output" / "windows_logs_parsed.csv"
            df_win = pd.DataFrame()
            if win_log_path.exists():
                try:
                    df_win = pd.read_csv(win_log_path)
                    # Robust Coercion
                    df_win['timestamp'] = pd.to_datetime(df_win['timestamp'], errors='coerce', utc=True)
                    df_win['timestamp'] = df_win['timestamp'].dt.tz_localize(None) 
                    df_win = df_win.dropna(subset=['timestamp'])
                except Exception as e: 
                    print(f"Skipping Windows Log correlation due to date error: {e}")
                    df_win = pd.DataFrame() # Reset on failure

            # Ensure timestamps for USB
            if 'timestamp' in df.columns:
                try:
                    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
                    df['timestamp'] = df['timestamp'].dt.tz_localize(None)
                    df = df.dropna(subset=['timestamp'])
                except Exception as e:
                    print(f"USB Timestamp conversion error: {e}")
                
            # A. RAPID INSERTION ( > 3 events in 5 minutes)
            df_sorted = df.sort_values('timestamp')
            for i in range(len(df_sorted)):
                row = df_sorted.iloc[i]
                ts = row['timestamp']
                # Look back 5 mins
                window_start = ts - pd.Timedelta(minutes=5)
                recent_count = len(df_sorted[(df_sorted['timestamp'] >= window_start) & (df_sorted['timestamp'] <= ts)])
                if recent_count >= 3:
                     threats.append({
                        "timestamp": ts,
                        "threat_type": "Multiple Rapid Insertions",
                        "severity": "HIGH",
                        "details": f"{recent_count} USB events detected within 5 minutes. Possible data exfiltration attempt."
                    })

            # B. ODD HOURS (11 PM - 5 AM)
            for _, row in df.iterrows():
                h = row['timestamp'].hour
                if h >= 23 or h <= 5:
                    threats.append({
                        "timestamp": row['timestamp'],
                        "threat_type": "USB Activity at Odd Hours",
                        "severity": "MEDIUM",
                        "details": f"Device activity detected at {h}:00. Potential Insider Threat."
                    })

            # C. UNKNOWN / NEW DEVICE (Simple Heuristic for Demo)
            # Flag if vendor is not Standard (e.g. 8086 Intel, 046d Logitech) or if it's explicitly "Unknown"
            # For demo, we can just flag 'Unknown' or specific suspicious VIDs if we had a list.
            # Here we'll flag if Model confidence is low but present, or just use the generic event.
            for _, row in df.iterrows():
                if row['vendor_id'] == "Unknown" or row['product_id'] == "Unknown":
                     threats.append({
                        "timestamp": row['timestamp'],
                        "threat_type": "Unknown / New USB Device",
                        "severity": "MEDIUM",
                        "details": "Unrecognized Vendor/Product ID. Possible Rogue Device."
                    })

            # D. CORRELATION: FAILED LOGINS
            if not df_win.empty and 'event_id' in df_win.columns:
                failed_logins = df_win[df_win['event_id'] == 4625]
                for _, row in df.iterrows():
                    ts = row['timestamp']
                    # Check for failed logins in the 30 mins PRIOR to USB
                    start_window = ts - pd.Timedelta(minutes=30)
                    relevant_fails = failed_logins[(failed_logins['timestamp'] >= start_window) & (failed_logins['timestamp'] <= ts)]
                    if not relevant_fails.empty:
                        threats.append({
                            "timestamp": ts,
                            "threat_type": "USB Used After Failed Logins",
                            "severity": "CRITICAL",
                            "details": f"{len(relevant_fails)} failed login attempts followed by USB insertion. Credentials + Data Theft Risk."
                        })

            # SAVE THREATS
            threat_output = BASE_DIR / "Output" / "usb_context_threats.csv"
            if threats:
                pd.DataFrame(threats).drop_duplicates().to_csv(threat_output, index=False)
                print(f"Contextual Threats saved → {threat_output.resolve()}")
            else:
                # Create empty
                pd.DataFrame(columns=["timestamp", "threat_type", "severity", "details"]).to_csv(threat_output, index=False)

            # --------------------------------------------------
            # ACTIVE RESPONSE INTEGRATION
            # --------------------------------------------------
            if threats:
                print(f"🚨 USB Threats Detected: {len(threats)}. Initiating Response...")
                ar = ActiveResponseModule()
                for t in threats:
                    if t.get('severity') in ['HIGH', 'CRITICAL']:
                        ar.execute_response(t.get('threat_type'), {
                            'severity': t.get('severity'),
                            'ip': 'Unknown', # USB is local
                            'username': 'Current User', 
                            'details': t.get('details')
                        })
                        
        except Exception as e:
            print(f"Advanced Threat Analysis Failed: {e}")

        df.to_csv(USB_LOG_FILE, index=False)
        print(f"USB logs saved → {USB_LOG_FILE.resolve()}")

    if suspicious:
        df_susp = pd.DataFrame(suspicious)
        df_susp.to_csv(USB_SUSPICIOUS_FILE, index=False)
        print(f"Suspicious USB events saved → {USB_SUSPICIOUS_FILE.resolve()}")
    else:
        # User Request: If no suspicious events, CLEAR the file (overwrite with empty)
        # preventing stale 2025 data from persisting.
        empty_df = pd.DataFrame(columns=["timestamp", "vendor_id", "product_id", "reason", "status"])
        empty_df.to_csv(USB_SUSPICIOUS_FILE, index=False)
        print("No suspicious events found. Cleared alert file.")


if __name__ == "__main__":
    save_usb_logs()