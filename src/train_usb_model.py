
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import joblib
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "Output"
MODEL_DIR = OUTPUT_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)

DATASET_FILE = DATA_DIR / "synthetic_usb_dataset.csv"
MODEL_FILE = MODEL_DIR / "usb_malware_model.joblib"
ENCODER_FILE = MODEL_DIR / "usb_encoders.joblib"

def train_model():
    print(f"Loading dataset from {DATASET_FILE}...")
    if not DATASET_FILE.exists():
        print("Dataset not found! Please generate it first.")
        return

    df = pd.read_csv(DATASET_FILE)
    
    # Feature Engineering
    # We need to encode categorical variables: vendor_id, product_id, is_weekend
    # hour and duration_seconds are numerical
    
    le_vendor = LabelEncoder()
    df['vendor_encoded'] = le_vendor.fit_transform(df['vendor_id'].astype(str))
    
    # Handle unseen labels in production by using a generic 'unknown' class or similar strategy? 
    # For this prototype we'll just stick to training distribution.
    
    X = df[['vendor_encoded', 'hour', 'duration_seconds', 'is_weekend']]
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Random Forest Classifier...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    print("Evaluating model...")
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))
    
    # Save artifacts
    joblib.dump(clf, MODEL_FILE)
    joblib.dump(le_vendor, ENCODER_FILE)
    
    print(f"Model saved to {MODEL_FILE}")
    print(f"Encoders saved to {ENCODER_FILE}")

if __name__ == "__main__":
    train_model()
