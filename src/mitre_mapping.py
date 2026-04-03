
# Maps Windows Event IDs to MITRE ATT&CK Techniques

MITRE_MAPPING = {
    4624: {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Defense Evasion"},
    4625: {"technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access"},
    4672: {"technique_id": "T1078", "technique_name": "Valid Accounts (Admin)", "tactic": "Privilege Escalation"},
    4688: {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution"},
    4720: {"technique_id": "T1136", "technique_name": "Create Account", "tactic": "Persistence"},
    4732: {"technique_id": "T1098", "technique_name": "Account Manipulation (Group)", "tactic": "Persistence"},
    4698: {"technique_id": "T1053", "technique_name": "Scheduled Task/Job", "tactic": "Execution"},
    7045: {"technique_id": "T1543", "technique_name": "Create or Modify System Process", "tactic": "Persistence"},
    # USB Events
    2003: {"technique_id": "T1200", "technique_name": "Hardware Additions (USB)", "tactic": "Initial Access"},
    2100: {"technique_id": "T1091", "technique_name": "Replication Through Removable Media", "tactic": "Lateral Movement"}, # Removal might imply transfer completion
    2102: {"technique_id": "T1052", "technique_name": "Exfiltration Over Physical Medium", "tactic": "Exfiltration"},
    6416: {"technique_id": "T1200", "technique_name": "Hardware Additions (New Device)", "tactic": "Initial Access"},
}

def get_mitre_info(event_id):
    """
    Returns (id, name, tactics) for a given Event ID.
    """
    if event_id in MITRE_MAPPING:
        return MITRE_MAPPING[event_id]
    return None
