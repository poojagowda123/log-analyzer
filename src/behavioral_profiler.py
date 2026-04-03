import json
from datetime import datetime
from pathlib import Path
from collections import defaultdict
import logging

# Setup Logging
logging.basicConfig(level=logging.INFO)

class BehavioralProfiler:
    def __init__(self, profile_path="user_profiles.json"):
        self.profile_path = Path(profile_path)
        self.profiles = self._load_profiles()
        
    def _load_profiles(self):
        if self.profile_path.exists():
            try:
                with open(self.profile_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logging.error(f"Failed to load profiles: {e}")
                return {}
        return {}

    def _save_profiles(self):
        try:
            with open(self.profile_path, 'w') as f:
                json.dump(self.profiles, f, indent=4)
        except Exception as e:
            logging.error(f"Failed to save profiles: {e}")

    def update_profile(self, user, event_data):
        """
        Updates the user's profile with new activity.
        event_data: dict with 'hour', 'ip', 'event_id'
        """
        if user not in self.profiles:
            self.profiles[user] = {
                "seen_ips": [],
                "active_hours": [],
                "total_events": 0,
                "first_seen": str(datetime.now())
            }
        
        profile = self.profiles[user]
        
        # Update IP
        ip = event_data.get('ip')
        if ip and ip not in profile["seen_ips"]:
            profile["seen_ips"].append(ip)
            
        # Update Hours (Simple frequency count could be better, but list of unique active hours for now)
        hour = event_data.get('hour')
        if hour is not None and hour not in profile["active_hours"]:
            profile["active_hours"].append(hour)
            
        profile["total_events"] += 1
        profile["last_seen"] = str(datetime.now())
        
        self._save_profiles()

    def check_deviation(self, user, event_data):
        """
        Calculates a deviation score (0.0 to 1.0).
        Higher score = more anomalous.
        """
        if user not in self.profiles:
            # First time seeing user? Moderate risk, but legitimate for new employees.
            # We'll return 0.5 to flag it gently.
            return 0.5, ["New User"]

        profile = self.profiles[user]
        score = 0.0
        reasons = []
        
        # 1. New IP Check
        ip = event_data.get('ip')
        if ip and ip not in ['127.0.0.1', '::1', 'Unknown']:
            if ip not in profile["seen_ips"]:
                score += 0.4
                reasons.append(f"New IP Address ({ip})")
        
        # 2. Unusual Hour Check
        hour = event_data.get('hour')
        if hour is not None:
             if hour not in profile["active_hours"]:
                 # Check distance from nearest active hour
                 min_diff = 24
                 for h in profile["active_hours"]:
                     diff = abs(hour - h)
                     if diff > 12: diff = 24 - diff # Wrap around
                     if diff < min_diff: min_diff = diff
                 
                 # If we are > 3 hours away from normal, flat anomaly
                 if min_diff > 3:
                     score += 0.3
                     reasons.append(f"Unusual Activity Hour ({hour}:00)")
        
        return min(score, 1.0), reasons

if __name__ == "__main__":
    # Test
    bp = BehavioralProfiler()
    user = "TEST_USER"
    bp.update_profile(user, {"hour": 9, "ip": "192.168.1.5"})
    bp.update_profile(user, {"hour": 10, "ip": "192.168.1.5"})
    
    score, reasons = bp.check_deviation(user, {"hour": 3, "ip": "10.0.0.99"})
    print(f"Deviation Score: {score}, Reasons: {reasons}")
