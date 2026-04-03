
import pandas as pd
import requests
import json
from pathlib import Path
import random

# Mock Suspicious IPs for demo (since we don't have a paid API key)
# In production, replace with real API calls to AbuseIPDB or VirusTotal
KNOWN_BAD_IPS = [
    "192.168.1.105", # Example local attacker
    "10.0.0.99",
    "45.33.32.156",  # Random public IP often flagged
    "185.156.175.12",
    "5.188.62.77"
]

def check_ip_reputation(ip):
    """
    Check IP against local blocklist and (optional) external API.
    Returns: (is_malicious, risk_score, source)
    """
    if str(ip) in KNOWN_BAD_IPS:
        return True, 100, "Local Blocklist"
    
    # Mock API call simulation
    # if random.random() < 0.01: return True, 80, "Heuristic Analysis"
    
    return False, 0, "Safe"

def enrich_logs_with_threat_intel(df):
    """
    Apply threat intel to a dataframe of logs.
    """
    print("Running Threat Intelligence Enrichment...")
    if 'ip' not in df.columns:
        return df
    
    results = df['ip'].apply(check_ip_reputation)
    
    # Unpack results
    df['is_threat'] = [r[0] for r in results]
    df['threat_score'] = [r[1] for r in results]
    df['threat_source'] = [r[2] for r in results]
    
    return df

if __name__ == "__main__":
    # Test
    print(check_ip_reputation("192.168.1.105"))
