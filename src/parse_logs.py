import re
from pathlib import Path
from dateutil import parser as dateparser

log_file = Path("../data/logs/auth.log")

# Regular expression for parsing auth.log lines
pattern = re.compile(
    r'^(?P<ts>\w+\s+\d+\s[\d:]+)\s+(?P<host>\S+)\s+(?P<service>[\w\-\[\]]+):\s+(?P<msg>.+)$'
)

def parse_log_line(line):
    match = pattern.match(line)
    if not match:
        return None
    
    ts = dateparser.parse(match.group('ts') + " 2024")  # year required for parser
    msg = match.group('msg')

    # Extract IP
    ip_match = re.search(r'from\s(\d+\.\d+\.\d+\.\d+)', msg)
    ip = ip_match.group(1) if ip_match else None

    # Extract username
    user_match = re.search(r'user\s(\w+)', msg)
    user = user_match.group(1) if user_match else None

    # Check event type
    if "Failed password" in msg:
        event = "Failed Login"
    elif "Accepted password" in msg:
        event = "Successful Login"
    else:
        event = "Other"

    return {
        "timestamp": ts,
        "username": user,
        "ip": ip,
        "event": event,
        "raw_message": msg
    }

def parse_logs():
    results = []
    with open(log_file, "r") as f:
        for line in f:
            parsed = parse_log_line(line.strip())
            if parsed:
                results.append(parsed)
    
    return results

# Run parser
if __name__ == "__main__":
    parsed_logs = parse_logs()
    for entry in parsed_logs:
        print(entry)
