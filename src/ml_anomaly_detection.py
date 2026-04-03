import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
from active_response import ActiveResponseModule
from behavioral_profiler import BehavioralProfiler

# --------------------------------------------------
import time
from datetime import datetime

# CONFIGURATION & PATHS
# --------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
WIN_INPUT = BASE_DIR / "Output" / "windows_logs_parsed.csv"
USB_INPUT = BASE_DIR / "Output" / "usb_logs_parsed.csv"
OUTPUT = BASE_DIR / "Output" / "ml_anomalies.csv"

def check_stale_data(filepath):
    if not filepath.exists(): return
    mtime = filepath.stat().st_mtime
    age_hours = (time.time() - mtime) / 3600
    if age_hours > 24:
        print("\n" + "!"*60)
        print(f"WARNING: Input file '{filepath.name}' is STALE!")
        print(f"Last modified: {datetime.fromtimestamp(mtime)}")
        print(f"It is {age_hours:.1f} hours old.")
        print("Run 'parse_windows_logs.py' (as Admin) to refresh data.")
        print("!"*60 + "\n")

check_stale_data(WIN_INPUT)
RF_OUTPUT = BASE_DIR / "Output" / "attack_identifications.csv"

# IGNORE SYSTEM ACCOUNTS
IGNORE_USERS = [
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "DWM-1", "DWM-2", "UMFD-0", "UMFD-1",
    "DEFAULTACCOUNT", "ANONYMOUS LOGON", "NT",
    "S-1-5-18", "S-1-5-19", "S-1-5-20",
    "Backup", "Backup Operators"
]

TRUSTED_IPS = ["127.0.0.1", "::1"]

# --------------------------------------------------
# DATA LOADING & PREPROCESSING
# --------------------------------------------------
def load_and_preprocess():
    print("Loading data for Enhanced ML Analysis...")
    all_data = []

    # 1. Load Windows Logs
    if WIN_INPUT.exists():
        df_win = pd.read_csv(WIN_INPUT)
        df_win['source'] = 'windows'
        all_data.append(df_win)

    # 2. Load USB Logs
    if USB_INPUT.exists():
        df_usb = pd.read_csv(USB_INPUT)
        df_usb['source'] = 'usb'
        # Normalize columns (User Request: Align with Windows)
        if 'raw_message' in df_usb.columns:
            df_usb = df_usb.rename(columns={'raw_message': 'message'})
        # ensure threat_score is treated as numeric
        if 'threat_score' in df_usb.columns:
            df_usb['threat_score'] = pd.to_numeric(df_usb['threat_score'], errors='coerce').fillna(0)
            
        all_data.append(df_usb)

    if not all_data:
        print("No log data found to analyze.")
        return None

    df = pd.concat(all_data, ignore_index=True)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["username"] = df["username"].astype(str).fillna("Unknown")
    df = df.sort_values("timestamp")

    # Filter Ignore List
    df_clean = df[~df["username"].isin(IGNORE_USERS)].copy()
    df_clean = df_clean[~df_clean["username"].str.contains("S-1-", na=False)]

    # --------------------------------------------------
    # ADVANCED FEATURE ENGINEERING (User + Creative)
    # --------------------------------------------------
    
    # 1. Basic Time Features
    df_clean["hour"] = df_clean["timestamp"].dt.hour
    df_clean["weekday"] = df_clean["timestamp"].dt.weekday
    df_clean["event_id"] = pd.to_numeric(df_clean["event_id"], errors="coerce").fillna(0)

    # 2. Circular Time Encoding (Creative Enhancement)
    # Preserves the cyclic nature of time (23:00 is close to 00:00)
    df_clean['hour_sin'] = np.sin(2 * np.pi * df_clean['hour'] / 24)
    df_clean['hour_cos'] = np.cos(2 * np.pi * df_clean['hour'] / 24)

    # 3. IP Analysis (User Request)
    if 'ip' not in df_clean.columns:
        df_clean['ip'] = "Unknown"
    else:
        df_clean['ip'] = df_clean['ip'].fillna("Unknown")

    # Count failed logins per IP (User Feature)
    failed_per_ip = df_clean[df_clean["event_id"] == 4625].groupby("ip").size()
    df_clean["failed_logins_per_ip"] = df_clean["ip"].map(failed_per_ip).fillna(0)

    # 4. Sequence Analysis (User Feature)
    # Did a successful login happen immediately after a failure?
    df_clean["prev_event_id"] = df_clean.groupby("username")["event_id"].shift(1)
    df_clean["successful_after_failed"] = (
        (df_clean["event_id"] == 4624) & (df_clean["prev_event_id"] == 4625)
    ).astype(int)

    # 5. Encodings
    le_user = LabelEncoder()
    df_clean["user_code"] = le_user.fit_transform(df_clean["username"])
    df_clean["source_code"] = LabelEncoder().fit_transform(df_clean["source"])

    return df_clean

# --------------------------------------------------
# ANOMALY NAMING
# --------------------------------------------------
def name_anomaly(row):
    """Naming logic merging user's specific rules with general heuristic."""
    
    # User's Logic
    # Comprehensive Event ID Map for Anomaly Naming
    EVENT_DESCRIPTIONS = {
        4624: "Anomalous Logon Session",
        4625: "Failed Login Pattern",
        4634: "Anomalous Logoff Activity",
        4647: "User Initiated Logoff Anomaly",
        4648: "Suspicious Explicit Credential Usage",
        4672: "Privilege Escalation Activity",
        4720: "Suspicious Account Creation",
        4722: "User Account Enabled",
        4723: "Attempt to Change Password",
        4724: "Password Reset Attempt",
        4725: "Account Disabled",
        4726: "User Account Deleted",
        4728: "Member Added to Security Group",
        4732: "Member Added to Local Group",
        4738: "User Account Modified",
        4756: "Member Added to Universal Group",
        4798: "Group Membership Enumeration",
        4799: "Security Group Management Enumeration",
        1102: "Audit Log Cleared",
        4663: "Suspicious Object Access",
        4688: "Suspicious Process Creation",
        4698: "Scheduled Task Created",
        5058: "Key File Operation",
        5059: "Key File Operation",
        5140: "Network Share Object Acessed",
        5145: "Detailed Network Share Check",
        # USB
        2003: "USB Mass Storage Connected",
        2100: "USB Device Activity",
        400: "Device Enumeration",
    }
    
    # 1. Check Event ID Map first
    eid = int(row.get("event_id", 0))
    desc = EVENT_DESCRIPTIONS.get(eid)
    
    if desc:
        # Append context if available
        if eid == 4624 and (row["hour"] < 6 or row["hour"] > 22):
            return f"{desc} (After Hours)"
        return desc

    # 2. Existing Special Logic (Fallbacks)
    # Lowered threshold for sensitivity (User feedback)
    if row["failed_logins_per_ip"] >= 3:
        if row["ip"] in ["Unknown", "127.0.0.1", "::1"]:
            return "Brute Force Attack (Local/Console)"
        return "Brute Force Attack from IP"
    
    if row["successful_after_failed"] == 1:
        return "Possible Account Compromise"
    
    if row["source"] == 'usb' and row["event_id"] in [2003, 2100]:
         return "Suspicious USB Activity"

    # Time anomalies
    if 0 <= row["hour"] < 5:
        return f"Late Night Activity (Event {eid})"
        
    if (row["hour"] < 6 or row["hour"] > 22):
        return f"After-Hours Activity (Event {eid})"

    return f"Statistical Anomaly (Event {eid})"

def assign_severity(name):
    high = ["Brute Force Attack from IP", "Brute Force Attack (Local/Console)", "Possible Account Compromise (Success after Fail)", "Privilege Escalation", "Suspicious USB Activity"]
    medium = ["Unusual After-Hours Activity"]
    if name in high: return "HIGH"
    if name in medium: return "MEDIUM"
    return "LOW"

# --------------------------------------------------
# MODELS
# --------------------------------------------------
def run_enhanced_detection(df):
    
    # Feature Selection (Including new advanced features)
    features = df[[
        "event_id", "hour_sin", "hour_cos", "weekday", 
        "user_code", "source_code", "failed_logins_per_ip", "successful_after_failed"
    ]]
    
    # 1. Isolation Forest (Unsupervised)
    print("Training Isolation Forest...")
    iso = IsolationForest(n_estimators=300, contamination=0.03, random_state=42)
    iso.fit(features)
    df["ml_score"] = iso.decision_function(features)
    df["is_anomaly"] = iso.predict(features) # -1 is anomaly

    # 2. Random Forest (Supervised logic for known attacks)
    print("Training Random Forest Classifier...")
    # Label known attacks for training RF
    # Label known attacks for training RF (Heuristic Labeling for Supervised Learning)
    # The user specifically requested ~6 identifiable categories for real-time logs.
    df['attack_label'] = 'Normal'
    
    # 1. Authentication Failure (Event 4625)
    # Catches "wrong password" attempts immediately.
    df.loc[df['event_id'] == 4625, 'attack_label'] = 'Login Attempt Failed'
    
    # 2. Privilege Escalation (Event 4672)
    df.loc[df['event_id'] == 4672, 'attack_label'] = 'Privilege Escalation'
    
    # 3. Account Manipulation (Event 4720, 4738 - User Created/Modified)
    df.loc[df['event_id'].isin([4720, 4738, 4722, 4723, 4724, 4725, 4726]), 'attack_label'] = 'Account Manipulation'
    
    # 4. Security Log Cleared (Event 1102)
    df.loc[df['event_id'] == 1102, 'attack_label'] = 'Security Log Cleared'
    
    # 5. Persistence Mechanism (Event 4698 - Scheduled Task)
    df.loc[df['event_id'].isin([4698, 7045]), 'attack_label'] = 'Persistence Mechanism'
    
    # 6. Physical Intrusion (USB)
    df.loc[df['source'] == 'usb', 'attack_label'] = 'Physical Intrusion'
    
    # 7. Late Night Access (Time-based)
    df.loc[(df['hour'] >= 0) & (df['hour'] < 5) & (df['attack_label'] == 'Normal'), 'attack_label'] = 'Unusual Access (Late Night > 12AM)'
    
    # Train RF
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(features, df['attack_label'])
    
    df['identified_attack'] = rf.predict(features)
    df['attack_confidence'] = np.max(rf.predict_proba(features), axis=1)

    # --------------------------------------------------
    # 3. BEHAVIORAL PROFILING (Stateful Analysis)
    # --------------------------------------------------
    print("Running Behavioral Profiling...")
    profiler = BehavioralProfiler()
    
    def apply_profiling(row):
        user = row.get('username', 'Unknown')
        if user in ['Unknown', 'SYSTEM']: return 0.0, ""
        
        # Check current event
        score, reasons = profiler.check_deviation(user, {
            'hour': row.get('hour'),
            'ip': row.get('ip'),
            'event_id': row.get('event_id')
        })
        
        # Update profile for future (Online Learning)
        # Only update if it's NOT an attack, to avoid poisoning the profile
        if row['identified_attack'] == 'Normal':
            profiler.update_profile(user, {
                'hour': row.get('hour'),
                'ip': row.get('ip')
            })
            
        return score, ", ".join(reasons)

    # Vectorized Apply is hard with state updates, so we use apply
    profiling_results = df.apply(apply_profiling, axis=1)
    df['deviation_score'] = profiling_results.apply(lambda x: x[0])
    df['deviation_reasons'] = profiling_results.apply(lambda x: x[1])

    # Flag High Deviation
    df.loc[df['deviation_score'] > 0.6, 'is_anomaly'] = -1
    df.loc[df['deviation_score'] > 0.6, 'anomaly_name'] = "Behavioral Deviation: " + df['deviation_reasons']

    # --------------------------------------------------

    # 4. Post-Processing
    df["anomaly_name"] = df.apply(name_anomaly, axis=1)
    df["severity"] = df["anomaly_name"].apply(assign_severity)

    return df

# --------------------------------------------------
# MAIN EXECUTION
# --------------------------------------------------
def main():
    df = load_and_preprocess()
    if df is None: return

    df_result = run_enhanced_detection(df)

    # Save Anomalies
    # We save rows that are EITHER statistical anomalies OR identified attacks
    anomalies = df_result[
        (df_result["is_anomaly"] == -1) | 
        (df_result["identified_attack"] != 'Normal')
    ].copy()
    
    # Keep useful columns
    out_cols = [
        "timestamp", "event_id", "source", "username", "ip", 
        "anomaly_name", "severity", "identified_attack", "ml_score", "message"
    ]
    # Ensure columns exist
    final_cols = [c for c in out_cols if c in anomalies.columns]
    
    # Save Anomalies
    print(f"Detected {len(anomalies)} anomalies in system logs.")
    
    # --------------------------------------------------
    # CONSOLE REPORT (User Request)
    # --------------------------------------------------
    if not anomalies.empty:
        print("\n--- 🕵️ SUSPICIOUS ACTIVITY REPORT 🕵️ ---")
        # Sort by timestamp
        anomalies_sorted = anomalies.sort_values('timestamp')
        for _, row in anomalies_sorted.tail(20).iterrows(): # Show last 20 to avoid spam
            ts = row.get('timestamp', 'Unknown Time')
            desc = row.get('anomaly_name', 'Anomaly')
            user = row.get('username', 'Unknown')
            ip = row.get('ip', 'Unknown')
            
            # Highlight Login Failures specifically
            if 'Login Attempt Failed' in str(row.get('attack_label', '')):
                desc = f"⚠️ FAILED LOGIN ({desc})"
                
            print(f"[{ts}] {desc} | User: {user} | IP: {ip}")
        print("-------------------------------------------\n")
    
    # User Request: Ensure dashboard columns exist
    if 'failed_count' not in anomalies.columns: anomalies['failed_count'] = 0
    if 'identified_attack' not in anomalies.columns: anomalies['identified_attack'] = "Unknown Anomaly"
    if 'severity' not in anomalies.columns: anomalies['severity'] = "MEDIUM"
    if 'anomaly_name' not in anomalies.columns: anomalies['anomaly_name'] = "Behavioral Anomaly"
    if 'attack_confidence' not in anomalies.columns: anomalies['attack_confidence'] = 0.50 # Default for unsupervised
    
    # Map Event IDs to descriptions for better naming
    def get_anomaly_name(row):
        if row['source'] == 'usb': return f"USB Anomaly (Vendor: {row.get('vendor_id','?')})"
        eid = str(row.get('event_id',''))
        if eid == '4625': return "Abnormal Login Failure Pattern"
        if eid == '4672': return "Unusual Privilege Assignment"
        return f"Statistical Anomaly (Event {eid})"

    anomalies['anomaly_name'] = anomalies.apply(get_anomaly_name, axis=1)

    anomalies.to_csv(OUTPUT, index=False)
    print(f"Saved anomalies to {OUTPUT}")
    
    # Save Attack Specifics (Retro-compatibility)
    attacks = df_result[df_result["identified_attack"] != 'Normal']
    attacks.to_csv(RF_OUTPUT, index=False)
    print(f"✅ Attack Identifications saved to: {RF_OUTPUT}")

    # --------------------------------------------------
    # ACTIVE RESPONSE (Merged from active_response.py)
    # --------------------------------------------------
    FIREWALL_LOG = BASE_DIR / "Output" / "firewall_blocklist.log"
    print("\n--- Active Response Module ---")
    
    # Filter for HIGH severity
    high_risk = anomalies[anomalies['severity'] == 'HIGH'].copy()
    
    if not high_risk.empty:
        print(f"🚨 Detected {len(high_risk)} HIGH severity threats. Initiating BLOCK...")
        
        # Initialize Active Response
        ar = ActiveResponseModule()
        
        with open(FIREWALL_LOG, "a") as f:
            for _, row in high_risk.iterrows():
                timestamp = row.get('timestamp', str(time.time()))
                ip = row.get('ip', 'Unknown')
                user = row.get('username', 'Unknown')
                reason = row.get('anomaly_name', 'Unknown Threat')
                
                # EXECUTE ACTIVE RESPONSE
                ar.execute_response(reason, {
                    'severity': 'HIGH',
                    'ip': ip,
                    'username': user,
                    'user': user
                })
                
                log_entry = f"[{timestamp}] BLOCK_ACTION: IP={ip} User={user} Reason={reason}\n"
                f.write(log_entry)
                print(f"   🚫 BLOCKED IP: {ip} for {reason}")
        print(f"✅ Response Complete. Actions logged to {FIREWALL_LOG}")
    else:
        print("No HIGH severity threats detected. No active response required.")

if __name__ == "__main__":
    main()
