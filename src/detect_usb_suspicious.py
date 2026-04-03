import pandas as pd
from pathlib import Path

INPUT = Path("../output/usb_logs_parsed.csv")
OUTPUT = Path("../output/usb_suspicious_events.csv")

# Unauthorized / suspicious USB vendor IDs
SUSPICIOUS_VENDORS = ["0000", "FFFF", "28E9", "AB12"]

def detect_usb():
    df = pd.read_csv(INPUT)
    alerts = []

    for _, row in df.iterrows():
        
        # Rule 1: USB device connected
        if row["event_id"] == 2003:
            alerts.append({
                "type": "USB Device Connected",
                "timestamp": row["timestamp"],
                "vendor": row["vendor_id"],
                "product": row["product_id"]
            })

        # Rule 2: Suspicious vendor ID
        if str(row["vendor_id"]) in SUSPICIOUS_VENDORS:
            alerts.append({
                "type": "Suspicious USB Vendor",
                "timestamp": row["timestamp"],
                "vendor": row["vendor_id"],
                "product": row["product_id"]
            })

        # Rule 3: USB Device Removed
        if row["event_id"] == 2100:
            alerts.append({
                "type": "USB Device Removed",
                "timestamp": row["timestamp"]
            })

    df_out = pd.DataFrame(alerts)
    df_out.to_csv(OUTPUT, index=False)
    print(f"USB suspicious activity saved → {OUTPUT.resolve()}")


if __name__ == "__main__":
    detect_usb()
