
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta
import random

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "Output"
OUTPUT_DIR.mkdir(exist_ok=True)
DATASET_FILE = BASE_DIR / "data" / "synthetic_usb_dataset.csv"
(BASE_DIR / "data").mkdir(exist_ok=True)

def generate_dataset(n_samples=2000):
    print("Generating synthetic USB dataset...")
    
    # Define Safe and Malicious scenarios
    
    # SAFE: Common vendors, normal hours, standard devices
    safe_vendors = ["046D", "03F0", "045E", "1050", "0781", "0951", "13FE", "05AC", "17EF"] # Logitech, HP, Microsoft, Yubico, SanDisk, Kingston, etc.
    safe_products = ["C52B", "C077", "0040", "0120", "5567", "1666", "3245", "1102"] 
    safe_devices = ["USB Flash Drive", "Wireless Mouse", "USB Keyboard", "External HDD", "YubiKey"]

    # MALICIOUS: Risk vendors, odd hours, rapid removal, specific "BadUSB" profiles
    suspicious_vendors = ["2341", "1D50", "05C6", "1234", "DEAD", "BEEF", "16C0"] # Arduino (sometimes), Hackney, Qualcomm (if unexpected), etc.
    suspicious_products = ["0043", "607d", "8036", "0001", "1337"]
    suspicious_devices = ["Rubber Ducky", "Bash Bunny", "Unknown HID", "Keylogger Injector", "Malicious Drive"]

    data = []
    
    start_time = datetime.now() - timedelta(days=90)
    
    for _ in range(n_samples):
        is_malicious = random.random() < 0.15 # 15% malicious
        
        timestamp = start_time + timedelta(minutes=random.randint(0, 90*24*60))
        hour = timestamp.hour
        
        if is_malicious:
            # Malicious traits:
            # - More likely at night (20:00 - 06:00)
            # - Suspicious Vendor IDs
            # - Rapid connect/disconnect (simulated by duration = 0 or very small)
            
            # 40% chance of happening at weird hours
            if random.random() < 0.4:
                timestamp = timestamp.replace(hour=random.choice([0, 1, 2, 3, 4, 21, 22, 23]))
                hour = timestamp.hour
                
            vendor = random.choice(suspicious_vendors) if random.random() < 0.8 else random.choice(safe_vendors) # Sometimes they spoof safe IDs
            product = random.choice(suspicious_products)
            device_type = random.choice(suspicious_devices)
            
            # Rapid disconnect for some attacks (Rubber Ducky often types and leaves, or just stays)
            # We'll simulate 'duration_seconds' as a feature
            duration = random.choice([1, 2, 5, 10]) if random.random() < 0.5 else random.randint(300, 3600)
            
            label = 1
            
        else:
            # Safe traits
            # - Work hours usually (08:00 - 18:00)
            # - Safe Vendors
            
            if random.random() < 0.8: # 80% during work hours
                timestamp = timestamp.replace(hour=random.randint(8, 19))
                hour = timestamp.hour
                
            vendor = random.choice(safe_vendors)
            product = random.choice(safe_products)
            device_type = random.choice(safe_devices)
            duration = random.randint(60, 28800) # 1 min to 8 hours
            
            label = 0
            
        data.append({
            "timestamp": timestamp,
            "vendor_id": vendor,
            "product_id": product,
            "device_type": device_type, # Can be used for descriptive analysis, model might ignore if not encoded
            "duration_seconds": duration,
            "hour": hour,
            "is_weekend": 1 if timestamp.weekday() >= 5 else 0,
            "label": label
        })
        
    df = pd.DataFrame(data)
    df.to_csv(DATASET_FILE, index=False)
    print(f"Generated {n_samples} samples. Saved to {DATASET_FILE}")
    
if __name__ == "__main__":
    generate_dataset()
