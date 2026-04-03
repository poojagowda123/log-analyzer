import pandas as pd
from pathlib import Path

INPUT = Path("../output/windows_logs_parsed.csv")
OUTPUT = Path("../output/suspicious_events.csv")


# SYSTEM ACCOUNTS TO IGNORE

SYSTEM_USERS = [
    "LOCAL SERVICE", "NETWORK SERVICE", "SYSTEM",
    "DWM-1", "DWM-2", "UMFD-0", "UMFD-1", "NT",
    "DEFAULTACCOUNT", "ANONYMOUS LOGON", "WINDOW MANAGER"
]




# LOAD & CLEAN LOGS

def load_logs():
    df = pd.read_csv(INPUT)

    # Convert timestamp column
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

    # Username: convert to string & replace NaN
    df['username'] = df['username'].astype(str).fillna("Unknown")

    return df



# RULE 1 — BRUTE FORCE DETECTION

def detect_failed_logins(df):
    failed = df[df['event_id'] == 4625]  # Failed login

    alerts = []
    counts = failed['username'].value_counts()

    for username, count in counts.items():
        if username not in SYSTEM_USERS and count >= 3:
            alerts.append({
                "type": "Brute Force Suspected",
                "username": username,
                "failed_attempts": count,
                "timestamp": failed[failed['username'] == username]['timestamp'].max()
            })

    return alerts


# RULE 2 — ADMIN LOGIN DETECTION

def detect_successful_admin(df):
    admin_events = df[
        (df['event_id'] == 4624) &
        (df['username'].str.contains("admin", case=False, na=False))
    ]

    alerts = []
    for _, row in admin_events.iterrows():
        alerts.append({
            "type": "Admin Login Detected",
            "username": row['username'],
            "timestamp": row['timestamp']
        })

    return alerts



# RULE 3 — PRIVILEGE ESCALATION

def detect_privilege(df):
    alerts = []

    # Remove system usernames
    priv = df[(df['event_id'] == 4672) & (~df['username'].isin(SYSTEM_USERS))]

    # Rule A — Privilege escalation at unusual hours
    for _, row in priv.iterrows():
        hour = row['timestamp'].hour if pd.notna(row['timestamp']) else None
        if hour is not None and (hour < 6 or hour > 22):
            alerts.append({
                "type": "Suspicious Privilege Escalation (Odd Hours)",
                "username": row['username'],
                "timestamp": row['timestamp']
            })

    # Rule B — Repeated privilege escalation events
    grouped = priv.groupby('username')
    for username, group in grouped:
        count = len(group)
        if count >= 5:
            alerts.append({
                "type": "Repeated Privilege Escalation",
                "username": username,
                "count": count,
                "timestamp": group['timestamp'].max()
            })

    return alerts



# MAIN FUNCTION

def main():
    df = load_logs()
    alerts = []

    # Add detections
    alerts.extend(detect_failed_logins(df))
    alerts.extend(detect_successful_admin(df))
    alerts.extend(detect_privilege(df))

    # Remove duplicate alerts
    alerts = [dict(t) for t in {tuple(d.items()) for d in alerts}]

    # Save alerts
    alert_df = pd.DataFrame(alerts)
    alert_df.to_csv(OUTPUT, index=False)

    print(f"Suspicious events saved to: {OUTPUT.resolve()}")


if __name__ == "__main__":
    main()
