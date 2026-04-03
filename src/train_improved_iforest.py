import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
import joblib

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT = BASE_DIR / "Output" / "windows_logs_parsed.csv"
MODEL_DIR = BASE_DIR / "Output" / "models"
MODEL_DIR.mkdir(exist_ok=True)

SCALER_PATH = MODEL_DIR / "scaler.joblib"
IF_MODEL_PATH = MODEL_DIR / "improved_iforest.joblib"

def load_data():
    df = pd.read_csv(INPUT)
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    
    df['event_id'] = pd.to_numeric(df['event_id'], errors='coerce').fillna(-1)
    df['username'] = df['username'].astype(str)
    
    df['hour'] = df['timestamp'].dt.hour.fillna(-1)
    df['weekday'] = df['timestamp'].dt.weekday.fillna(-1)
    
    df['user_code'] = df['username'].astype('category').cat.codes

    # IP present or not
    df['ip_present'] = (~df['ip'].isna() & (df['ip'] != 'None')).astype(int)

    # per-user event frequency
    df['user_freq'] = df.groupby('username').cumcount() + 1

    # total events per user
    total_user_events = df['username'].value_counts().to_dict()
    df['user_total'] = df['username'].map(total_user_events)

    # number of unique events per user
    unique_events = df.groupby('username')['event_id'].nunique().to_dict()
    df['user_unique_events'] = df['username'].map(unique_events)

    # time since last event for same user
    df = df.sort_values("timestamp")
    df['prev_time'] = df.groupby('username')['timestamp'].shift(1)
    df['secs_since_prev'] = (df['timestamp'] - df['prev_time']).dt.total_seconds().fillna(0)

    features = df[[
        'event_id',
        'hour',
        'weekday',
        'user_code',
        'ip_present',
        'user_freq',
        'user_total',
        'user_unique_events',
        'secs_since_prev'
    ]]

    return df, features

def train_iforest(features):
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features)

    joblib.dump(scaler, SCALER_PATH)
    print("Saved scaler.")

    model = IsolationForest(
        n_estimators=300,
        max_samples=0.9,
        contamination=0.025,   # 2.5% anomalies
        max_features=1.0,
        random_state=42,
        bootstrap=True
    )

    model.fit(X_scaled)
    joblib.dump(model, IF_MODEL_PATH)
    print("Saved improved Isolation Forest model.")

def main():
    df, features = load_data()
    print("Training on data:", features.shape)
    train_iforest(features)
    print("Improved IF model training completed.")

if __name__ == "__main__":
    main()
