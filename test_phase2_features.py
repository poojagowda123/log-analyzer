
import pandas as pd
import sys
from pathlib import Path

# Add src to path
BASE_DIR = Path(__file__).resolve().parent
sys.path.append(str(BASE_DIR / "src"))

from threat_intelligence import enrich_logs_with_threat_intel
from mitre_mapping import MITRE_MAPPING

def test_phase2():
    print("Testing Phase 2 Features...")
    
    # 1. Create Dummy Data
    df = pd.DataFrame([
        {"event_id": 4625, "ip": "192.168.1.105", "message": "Failed login"}, # Malicious IP, MITRE Brute Force
        {"event_id": 4624, "ip": "127.0.0.1", "message": "Success login"},    # Safe IP, MITRE Valid Accounts
        {"event_id": 9999, "ip": "10.0.0.5", "message": "Unknown event"}      # Unknown
    ])
    
    print("Original Data:")
    print(df)
    
    # 2. Test Threat Intel
    print("\n--- Testing Threat Intel ---")
    df = enrich_logs_with_threat_intel(df)
    print(df[['ip', 'is_threat', 'threat_score']])
    
    # 3. Test MITRE Mapping
    print("\n--- Testing MITRE Mapping ---")
    def get_mitre_tag(eid):
        if eid in MITRE_MAPPING:
            m = MITRE_MAPPING[eid]
            return f"{m['technique_id']} - {m['technique_name']}"
        return ""
        
    df['mitre_technique'] = df['event_id'].apply(get_mitre_tag)
    print(df[['event_id', 'mitre_technique']])
    
    # Validation
    if df.loc[0, 'is_threat'] == True and df.loc[0, 'mitre_technique'].startswith('T1110'):
        print("\nSUCCESS: Phase 2 Logic Verified.")
    else:
        print("\nFAILURE: Logic verification failed.")

if __name__ == "__main__":
    test_phase2()
