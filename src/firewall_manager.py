import subprocess
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(
    filename='firewall_manager.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class FirewallManager:
    def __init__(self):
        self.blocked_ips = set()

    def run_command(self, command):
        """Run a shell command and return output."""
        try:
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                logging.error(f"Command failed: {command}\nError: {result.stderr}")
                return False, result.stderr
            return True, result.stdout
        except Exception as e:
            logging.error(f"Execution error: {e}")
            return False, str(e)

    def block_ip(self, ip_address, rule_name="LogAnalyzer_Block"):
        """Blocks an IP address using Windows Firewall."""
        if ip_address in self.blocked_ips:
            logging.info(f"IP {ip_address} is already blocked.")
            return True

        print(f"Adding Firewall Block Rule for {ip_address}...")
        
        # Command to add block rule
        cmd = f"netsh advfirewall firewall add rule name=\"{rule_name}_{ip_address}\" dir=in action=block remoteip={ip_address}"
        
        success, output = self.run_command(cmd)
        if success:
            self.blocked_ips.add(ip_address)
            logging.info(f"Successfully BLOCKED IP: {ip_address}")
            print(f"✅ BLOCKED IP: {ip_address}")
            
            # Also block outbound just in case (C2 communication)
            cmd_out = f"netsh advfirewall firewall add rule name=\"{rule_name}_{ip_address}_OUT\" dir=out action=block remoteip={ip_address}"
            self.run_command(cmd_out)
            return True
        else:
            print(f"❌ Failed to block IP {ip_address}: {output}")
            return False

    def unblock_ip(self, ip_address, rule_name="LogAnalyzer_Block"):
        """Removes the block rule for an IP."""
        print(f"Unblocking IP {ip_address}...")
        
        cmd_in = f"netsh advfirewall firewall delete rule name=\"{rule_name}_{ip_address}\""
        cmd_out = f"netsh advfirewall firewall delete rule name=\"{rule_name}_{ip_address}_OUT\""
        
        self.run_command(cmd_in)
        self.run_command(cmd_out)
        
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
        
        logging.info(f"Unblocked IP: {ip_address}")
        print(f"✅ UNBLOCKED IP: {ip_address}")

    def isolate_machine(self):
        """Panic Button: Block all inbound traffic except essential services."""
        print("⚠️ INITIATING MACHINE ISOLATION ⚠️")
        logging.warning("Machine Isolation Triggered!")
        
        # Block all inbound
        # NOTE: This is dangerous, it might cut off remote access. 
        # Only use if seated at the machine or if you have an allowlist rule active.
        cmd = "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound"
        success, _ = self.run_command(cmd)
        
        if success:
            print("✅ Machine Isolated (Inbound Blocked).")
        else:
            print("❌ Isolation Failed.")

    def restore_normal_traffic(self):
        """Restore default firewall policy."""
        print("Restoring Normal Traffic...")
        cmd = "netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound"
        self.run_command(cmd)
        print("✅ Traffic Restored.")

if __name__ == "__main__":
    # Test
    fw = FirewallManager()
    # fw.block_ip("192.168.1.100")
    # fw.unblock_ip("192.168.1.100")
