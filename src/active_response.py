import logging
from datetime import datetime
from firewall_manager import FirewallManager
from process_monitor import ProcessMonitor

# Setup logging
logging.basicConfig(
    filename='active_response.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

import os

class ActiveResponseModule:
    def __init__(self):
        self.fw = FirewallManager()
        self.pm = ProcessMonitor()
        # Check Env Var for Dry Run
        self.dry_run = os.environ.get('LOGANALYZER_DRY_RUN') == '1'

    def execute_response(self, threat_type, details):
        """
        Decides and executes a response based on threat details.
        details: dict containing 'ip', 'pid', 'severity', etc.
        """
        severity = details.get('severity', 'LOW')
        ip = details.get('ip')
        pid = details.get('pid')
        user = details.get('username')
        
        logging.info(f"Analyzing Threat: {threat_type} ({severity})")

        if severity == 'HIGH' or severity == 'CRITICAL':
            self._handle_high_severity(threat_type, ip, pid, user)
        elif severity == 'MEDIUM':
            self._handle_medium_severity(threat_type, ip, user)
        
    def _handle_high_severity(self, threat, ip, pid, user):
        print(f"⚡ ACTIVE RESPONSE TRIGGERED for {threat} ⚡")
        
        # 1. Block Network if IP is present
        if ip and ip not in ['127.0.0.1', '::1', 'Unknown']:
            if not self.dry_run:
                self.fw.block_ip(ip)
            else:
                print(f"   [DRY RUN] Would BLOCK IP: {ip}")

        # 2. Kill Process if PID is present
        if pid:
            if not self.dry_run:
                self.pm.kill_process(pid)
            else:
                print(f"   [DRY RUN] Would KILL PID: {pid}")
                
        # 3. User Alert (Placeholder for UI verification)
        print(f"   ⚠️  USER ALERT: Critical Security Event detected for user {user}!")

    def _handle_medium_severity(self, threat, ip, user):
        # Just Log and Warn
        print(f"⚠️  WARNING: Suspicious activity detected ({threat}). Monitor Closely.")
        logging.warning(f"Medium Threat: {threat} from {ip} / {user}")

if __name__ == "__main__":
    ar = ActiveResponseModule()
    # Test
    ar.execute_response("Brute Force Test", {"severity": "HIGH", "ip": "10.0.0.99"})
