import time
import logging
import threading
from datetime import datetime
import argparse
import sys
import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Import Modules
from process_monitor import ProcessMonitor
from parse_windows_logs import save_to_csv as parse_windows
from parse_usb_logs import save_usb_logs as parse_usb
from ml_anomaly_detection import main as run_ml_detection
from firewall_manager import FirewallManager
from semantic_analysis import SemanticAnalyzer

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [DAEMON] - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("security_daemon.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

class SecurityDaemon:
    def __init__(self, interval=30):
        self.interval = interval
        self.running = False
        self.pm = ProcessMonitor()
        self.fw = FirewallManager()
        self.semantic_analyzer = SemanticAnalyzer()

    def run_process_scan(self):
        """Scans processes and kills bad ones."""
        logging.info("Running Process Scan...")
        bad_procs = self.pm.check_processes()
        if bad_procs:
            for p in bad_procs:
                logging.warning(f"Malicious Process Detected: {p['name']} ({p['pid']})")
                # Active Kill
                self.pm.kill_process(p['pid'])
    
    def run_log_analysis(self):
        """Parses logs and runs ML detection."""
        logging.info("Parsing Windows Logs...")
        try:
            parse_windows(limit=1000) # Incremental parse would be better, but limit is okay for loop
        except Exception as e:
            logging.error(f"Windows Log Parse Failed: {e}")

        logging.info("Parsing USB Logs...")
        try:
            parse_usb()
        except Exception as e:
            logging.error(f"USB Log Parse Failed: {e}")

        logging.info("Running ML Anomaly Detection & Active Response...")
        try:
            run_ml_detection()
        except Exception as e:
            logging.error(f"ML Detection Failed: {e}")

        logging.info("Running BERT Semantic Analysis...")
        try:
            self.semantic_analyzer.run_analysis()
        except Exception as e:
            logging.error(f"BERT Analysis Failed: {e}")

    def start(self):
        self.running = True
        print("\n" + "="*50)
        print("🛡️  LOGANALYZER ENDPOINT SECURITY DAEMON STARTED 🛡️")
        print("="*50)
        print(f"Loop Interval: {self.interval} seconds")
        print("Press Ctrl+C to stop.\n")

        try:
            while self.running:
                start_time = time.time()
                
                # 1. Real-time Process Check (Fast)
                self.run_process_scan()
                
                # 2. Log Analysis & ML (Slower)
                self.run_log_analysis()
                
                elapsed = time.time() - start_time
                logging.info(f"Cycle completed in {elapsed:.2f}s")
                
                # Wait for next cycle
                sleep_time = max(1, self.interval - elapsed)
                time.sleep(sleep_time)
                
        except KeyboardInterrupt:
            print("\n🛑 Stopping Security Daemon...")
            self.running = False

if __name__ == "__main__":
    if not is_admin():
        print("\n" + "!"*60)
        print("CRITICAL WARNING: FULL FUNCTIONALITY RESTRICTED")
        print("You are NOT running as Administrator.")
        print(" - Windows Security Logs CANNOT be read (Brute Force Detection disabled).")
        print(" - Firewall Blocking WILL FAIL.")
        print("Please restart your terminal as Administrator for full protection.")
        print("!"*60 + "\n")
        time.sleep(3) # Let them read it

    parser = argparse.ArgumentParser(description="LogAnalyzer Endpoint Security Daemon")
    parser.add_argument("--interval", type=int, default=30, help="Scan interval in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Run without taking active actions (logging only)")
    
    args = parser.parse_args()
    
    if args.dry_run:
        print("⚠️  DRY RUN MODE: No active blocking/killing will occur.")
        import os
        os.environ['LOGANALYZER_DRY_RUN'] = '1'
        
    daemon = SecurityDaemon(interval=args.interval)
    daemon.start()
