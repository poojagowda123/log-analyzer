import win32evtlog
import re
import pandas as pd
from pathlib import Path

# Advanced Features
try:
    from threat_intelligence import enrich_logs_with_threat_intel
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False

try:
    from mitre_mapping import MITRE_MAPPING
    MITRE_AVAILABLE = True
except ImportError:
    MITRE_AVAILABLE = False

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT = BASE_DIR / "Output"
OUTPUT.mkdir(exist_ok=True)


def _is_plausible_username(s: str) -> bool:
    """Return True if s looks like a user account (not a SID, hex, group token etc.)."""
    if not s or not isinstance(s, str):
        return False
    s = s.strip()
    if not s:
        return False
    # ignore SIDs
    if s.startswith("S-1-"):
        return False
    # ignore typical non-username tokens
    low = s.lower()
    bad_tokens = ("built", "builtin", "administrators", "workgroup", "system", "guest", "null", "<none>")
    if any(token in low for token in bad_tokens):
        return False
    # ignore hex or object ids
    if re.fullmatch(r"0x[0-9a-fA-F]+", s):
        return False
    # ignore pure numeric
    if re.fullmatch(r"\d+", s):
        return False
    # ignore UUID-like
    if re.fullmatch(r"[0-9a-fA-F\-]{8,}", s):
        return False
    # likely username if length reasonable
    if 1 < len(s) <= 256:
        return True
    return False


def extract_username(event):
    """
    Extract username from win32 event object using EventID-specific rules,
    falling back to scanning StringInserts for a plausible token.
    """
    inserts = event.StringInserts
    if not inserts:
        return "Unknown"

    # ensure list for indexing
    try:
        inserts_list = list(inserts)
    except Exception:
        inserts_list = [str(inserts)]

    eid = int(event.EventID) if event.EventID is not None else None

    # 4624 / 4625: Logon / failed logon - username commonly at index 5
    if eid in (4624, 4625):
        if len(inserts_list) > 5 and _is_plausible_username(inserts_list[5]):
            return inserts_list[5]

    # 4634: Logoff - often index 1
    if eid == 4634:
        if len(inserts_list) > 1 and _is_plausible_username(inserts_list[1]):
            return inserts_list[1]

    # 4672: Special privileges assigned to new logon - often index 1
    if eid == 4672:
        if len(inserts_list) > 1 and _is_plausible_username(inserts_list[1]):
            return inserts_list[1]

    # Group membership events (4798, 4799) - index 1 may be the account changed
    if eid in (4798, 4799):
        if len(inserts_list) > 1 and _is_plausible_username(inserts_list[1]):
            return inserts_list[1]

    # Account creation/modification range example (4720-4732)
    if eid and 4720 <= eid <= 4732:
        if len(inserts_list) > 1 and _is_plausible_username(inserts_list[1]):
            return inserts_list[1]
        if len(inserts_list) > 0 and _is_plausible_username(inserts_list[0]):
            return inserts_list[0]

    # Generic fallback: scan inserts for first plausible token
    for item in inserts_list:
        try:
            s = str(item).strip()
        except Exception:
            continue
        # sometimes list items contain tuples/strings with commas; try to extract tokens
        # split on common separators and test tokens
        candidates = re.split(r"[,\s\(\)\[\]{}:]+", s)
        for cand in candidates:
            if _is_plausible_username(cand):
                return cand

    # last fallback: try simple regex on full message
    msg = str(inserts_list)
    m = re.search(r"Account Name:\s*'?(?P<user>[A-Za-z0-9\-\_\.\\]+)'?", msg, re.IGNORECASE)
    if m:
        cand = m.group("user")
        if _is_plausible_username(cand):
            return cand

    return "Unknown"


def read_security_logs(limit=None):
    """
    Read Windows Security logs, parse fields and return list of dicts.
    `limit` can be used to stop after reading a number of events (helpful for testing).
    """
    handle = None
    try:
        handle = win32evtlog.OpenEventLog('localhost', 'Security')
    except Exception as e:
        if "1314" in str(e):
            print("\n" + "="*60)
            print("CRITICAL ERROR: Administrator Privileges Required")
            print("="*60)
            print("Accessing the Windows SECURITY log requires elevated privileges.")
            print("Please run this command from an ADMINISTRATOR Terminal / PowerShell.")
            print("="*60 + "\n")
        else:
            print(f"Failed to open Security log: {e}")
        return []

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    all_events = []
    count = 0

    while True:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        if not events:
            break

        for event in events:
            # optional limit for testing
            if limit and count >= limit:
                return all_events

            # safe extraction of message/inserts
            try:
                inserts = event.StringInserts
                message = str(inserts) if inserts is not None else ""
            except Exception:
                message = ""

            record = {
                "timestamp": event.TimeGenerated,
                "event_id": int(event.EventID) if event.EventID is not None else None,
                "source": event.SourceName if event.SourceName is not None else "",
                "message": message,  # Needed for forensic toggle
            }

            # Generate basic activity summary
            if event.EventID == 4624:
                summary = "Successful Logon"
            elif event.EventID == 4625:
                summary = "Failed Logon Attempt" 
            elif event.EventID == 4672:
                summary = "Special Privileges Assigned"
            else:
                summary = f"Event {event.EventID}"

            record["activity_summary"] = summary

            # Extract IP address if present in message
            ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', message)
            record["ip"] = ip_match.group(0) if ip_match else None

            # Extract username using event-aware extractor
            try:
                record["username"] = extract_username(event)
            except Exception:
                record["username"] = "Unknown"

            all_events.append(record)
            count += 1

    return all_events


def save_to_csv(limit=5000):
    print(f"Parsing generic Windows Logs (Limit: {limit} events)...")
    events = read_security_logs(limit=limit)

    if not events:
        print("\n" + "!"*60)
        print("WARNING: No events found!")
        print("This usually means you are NOT running as Administrator.")
        print("The 'windows_logs_parsed.csv' file has NOT been updated.")
        print("!"*60 + "\n")
        return

    df = pd.DataFrame(events)
    # Convert timestamp to ISO string for portability
    # Convert timestamp to ISO string for portability
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce").astype(str)

    # ---------------------------------------------------------
    # ENRICHMENT: Threat Intelligence & MITRE
    # ---------------------------------------------------------
    if THREAT_INTEL_AVAILABLE:
        try:
            df = enrich_logs_with_threat_intel(df)
        except Exception as e:
            print(f"Threat Intel Enrichment failed: {e}")

    if MITRE_AVAILABLE:
        print("Mapping events to MITRE ATT&CK Framework...")
        # Add MITRE columns
        # Optimized mapping using map/apply
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

    out_file = OUTPUT / "windows_logs_parsed.csv"
    df.to_csv(out_file, index=False)
    print(f"Saved structured logs to: {out_file.resolve()}")


if __name__ == "__main__":
    # for testing you can set a small limit: save_to_csv(limit=500)
    save_to_csv()
