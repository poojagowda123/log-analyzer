
import pandas as pd
from pathlib import Path
import os

BASE_DIR = Path(os.getcwd())
csv_path = BASE_DIR / "Output" / "windows_logs_parsed.csv"
ml_path = BASE_DIR / "Output" / "ml_anomalies.csv"

print(f"Checking: {csv_path}")
if csv_path.exists():
    t = os.path.getmtime(csv_path)
    print(f"Modified: {pd.to_datetime(t, unit='s')}")
    try:
        df = pd.read_csv(csv_path)
        print(f"Rows: {len(df)}")
        if 'timestamp' in df.columns:
            print(f"Latest Log Timestamp: {df['timestamp'].max()}")
    except Exception as e:
        print(f"Error reading CSV: {e}")
else:
    print("File not found.")

print("-" * 20)
print(f"Checking: {ml_path}")
if ml_path.exists():
    t = os.path.getmtime(ml_path)
    print(f"Modified: {pd.to_datetime(t, unit='s')}")
    try:
        df = pd.read_csv(ml_path)
        print(f"Rows: {len(df)}")
    except: pass
else:
    print("File not found.")
