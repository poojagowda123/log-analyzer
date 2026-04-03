import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from pathlib import Path
import joblib

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "Output"
WIN_LOGS = OUTPUT_DIR / "windows_logs_parsed.csv"
USB_LOGS = OUTPUT_DIR / "usb_logs_parsed.csv"
MODEL_PATH = OUTPUT_DIR / "rf_attack_classifier.pkl"
RESULTS_PATH = OUTPUT_DIR / "attack_identifications.csv"

def prepare_data():
    all_data = []
    
    # Load Windows Logs
    if WIN_LOGS.exists():
        df_win = pd.read_csv(WIN_LOGS)
        df_win['log_source'] = 'windows'
        df_win['timestamp'] = pd.to_datetime(df_win['timestamp'], errors='coerce')
        all_data.append(df_win)
        
    # Load USB Logs
    if USB_LOGS.exists():
        df_usb = pd.read_csv(USB_LOGS)
        df_usb['log_source'] = 'usb'
        df_usb['timestamp'] = pd.to_datetime(df_usb['timestamp'], errors='coerce')
        # Standardize columns for consolidation
        if 'raw_message' in df_usb.columns:
            df_usb = df_usb.rename(columns={'raw_message': 'message'})
        all_data.append(df_usb)
        
    if not all_data:
        print("No logs found to process.")
        return None
        
    df = pd.concat(all_data, ignore_index=True)
    df['hour'] = df['timestamp'].dt.hour
    df['weekday'] = df['timestamp'].dt.weekday
    
    # Fill NAs
    df['username'] = df['username'].fillna('Unknown')
    df['event_id'] = df['event_id'].fillna(0).astype(int)
    
    return df

def label_attacks(df):
    """
    Apply heuristic labeling for training the RF model.
    In a real scenario, this would be human-labeled data.
    """
    df['attack_type'] = 'Normal'
    
    # 1. Brute Force (Event ID 4625)
    df.loc[df['event_id'] == 4625, 'attack_type'] = 'Brute Force'
    
    # 2. Privilege Escalation (Event ID 4672)
    df.loc[df['event_id'] == 4672, 'attack_type'] = 'Privilege Escalation'
    
    # 3. Unauthorized USB (USB events with specific IDs)
    df.loc[(df['log_source'] == 'usb') & (df['event_id'].isin([2003, 2100])), 'attack_type'] = 'USB Intrusion'
    
    # 4. Credential Dumping (Simulated via account creation/mod 4720-4732)
    df.loc[(df['event_id'] >= 4720) & (df['event_id'] <= 4732), 'attack_type'] = 'Account Manipulation'
    
    # 5. Lateral Movement (Simulated via logins with IP addresses)
    df.loc[(df['event_id'] == 4624) & (df['ip'].notna()), 'attack_type'] = 'Lateral Movement'
    
    return df

def train_and_classify():
    df = prepare_data()
    if df is None: return
    
    df = label_attacks(df)
    
    # Feature Engineering
    le_user = LabelEncoder()
    df['user_encoded'] = le_user.fit_transform(df['username'].astype(str))
    
    le_source = LabelEncoder()
    df['source_encoded'] = le_source.fit_transform(df['log_source'])
    
    features = ['event_id', 'hour', 'weekday', 'user_encoded', 'source_encoded']
    X = df[features].fillna(0)
    y = df['attack_type']
    
    # Train RandomForest
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X, y)
    
    # Save Model
    joblib.dump({'model': rf, 'le_user': le_user, 'le_source': le_source}, MODEL_PATH)
    
    # Identify Attacks (Self-prediction to show identification on current logs)
    df['identified_attack'] = rf.predict(X)
    df['confidence'] = np.max(rf.predict_proba(X), axis=1)
    
    # Save results
    final_df = df[['timestamp', 'log_source', 'event_id', 'username', 'identified_attack', 'confidence']]
    final_df.to_csv(RESULTS_PATH, index=False)
    print(f"Attack identification complete. Results saved to {RESULTS_PATH}")

if __name__ == "__main__":
    train_and_classify()
