
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
import re
import logging

# Try importing advanced libraries
try:
    from sentence_transformers import SentenceTransformer, util
    import torch
    NLP_AVAILABLE = True
except ImportError:
    print("NLP libraries (sentence-transformers/torch) missing. Advanced features disabled.")
    NLP_AVAILABLE = False

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "Output"
WIN_LOGS = OUTPUT_DIR / "windows_logs_parsed.csv"
USB_LOGS = OUTPUT_DIR / "usb_logs_parsed.csv"
ATTACK_IDENT = OUTPUT_DIR / "attack_identifications.csv"

# Outputs
TF_OUTPUT = OUTPUT_DIR / "tfidf_results.csv"
TF_ATTACK_OUTPUT = OUTPUT_DIR / "tfidf_attack_keywords.csv"
BERT_OUTPUT = OUTPUT_DIR / "bert_results.csv"
NLP_THREATS = OUTPUT_DIR / "nlp_threats.csv"

class SemanticAnalyzer:
    def __init__(self):
        self.model = None
        if NLP_AVAILABLE:
            print("[SemanticAnalyzer] Loading BERT model (all-MiniLM-L6-v2)...")
            try:
                self.model = SentenceTransformer('all-MiniLM-L6-v2')
                print("[SemanticAnalyzer] Model loaded successfully.")
            except Exception as e:
                print(f"[SemanticAnalyzer] Failed to load model: {e}")
                self.model = None

    def load_data(self):
        all_msgs = []
        sources = []
        timestamps = []
        event_ids = []
        
        if WIN_LOGS.exists():
            try:
                df_win = pd.read_csv(WIN_LOGS)
                if not df_win.empty:
                    msgs = df_win['message'].astype(str).tolist()
                    all_msgs.extend(msgs)
                    sources.extend(['windows'] * len(msgs))
                    timestamps.extend(df_win['timestamp'].tolist())
                    event_ids.extend(df_win['event_id'].tolist())
            except Exception as e:
                print(f"[SemanticAnalyzer] Error loading Windows logs: {e}")
            
        if USB_LOGS.exists():
            try:
                df_usb = pd.read_csv(USB_LOGS)
                if not df_usb.empty:
                    msg_col = 'raw_message' if 'raw_message' in df_usb.columns else 'message'
                    msgs = df_usb[msg_col].astype(str).tolist()
                    all_msgs.extend(msgs)
                    sources.extend(['usb'] * len(msgs))
                    timestamps.extend(df_usb['timestamp'].tolist())
                    event_ids.extend(df_usb['event_id'].tolist())
            except Exception as e:
                print(f"[SemanticAnalyzer] Error loading USB logs: {e}")
            
        return pd.DataFrame({
            'timestamp': timestamps,
            'event_id': event_ids,
            'message': all_msgs,
            'source': sources
        })

    def perform_threat_classification(self, df):
        """
        Rule-based/NLP hybrid classification for specific threat patterns.
        Matches the user's requirement for 'Suspicious System Configuration (DCOM)' etc.
        """
        print("Running NLP Threat Classification...")
        threats = []
        
        # Define regex patterns for threats
        patterns = [
            (r"10016.*CLSID.*AppID", "Suspicious System Configuration (DCOM)"),
            (r"application-specific.*Local Activation", "Suspicious System Configuration (DCOM)"),
            (r"The server.*did not register with DCOM", "DCOM Server Registration Failed"),
            (r"audit policy.*was changed", "Security Policy Modification"),
            (r"7045.*Service was installed", "New Service Installation"),
            (r"defender.*failed", "Antivirus Defense Evasion"),
            (r"failed to start", "Service Failure"),
        ]
        
        for _, row in df.iterrows():
            msg = str(row['message'])
            for pat, attack_type in patterns:
                if re.search(pat, msg, re.IGNORECASE):
                    threats.append({
                        'event_id': row['event_id'],
                        'timestamp': row['timestamp'],
                        'message': msg,
                        'nlp_attack_type': attack_type,
                        'source': row['source']
                    })
                    break # Matched one pattern, move to next message

        if threats:
            threat_df = pd.DataFrame(threats)
            threat_df.to_csv(NLP_THREATS, index=False)
            print(f"Proprietary Threat Classification saved to {NLP_THREATS}")
        else:
            # Create empty file
            if not NLP_THREATS.exists(): 
                pd.DataFrame(columns=['event_id', 'timestamp', 'message', 'nlp_attack_type', 'source']).to_csv(NLP_THREATS, index=False)

    def perform_bert_advanced(self, df):
        """
        Advanced Semantic Analysis:
        1. K-Means Clustering for better 'normal' baselining
        2. Semantic Categorization
        3. Semantic Severity Scoring
        4. PCA Projection for Visualization
        """
        if not NLP_AVAILABLE or self.model is None:
            return

        print("Starting Advanced BERT Analysis...")
        messages = df['message'].tolist()
        
        try:
            # Sampling for performance (Process latest 2000 messages)
            sample_size = min(len(messages), 2000)
            df_sample = df.tail(sample_size).copy() 
            
            sampled_msgs = df_sample['message'].astype(str).tolist()
            if not sampled_msgs: return

            timestamps = df_sample['timestamp'].tolist()
            event_ids = df_sample['event_id'].tolist()
            
            # --- 1. Embeddings ---
            embeddings = self.model.encode(sampled_msgs)
            
            # --- 2. K-Means Clustering for Outlier Detection ---
            from sklearn.cluster import KMeans
            # Determine optimal clusters (simplified: sqrt of N/2, max 10)
            n_clusters = min(int(np.sqrt(len(sampled_msgs)/2)), 10)
            n_clusters = max(n_clusters, 2) # At least 2 clusters
            
            kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
            kmeans.fit(embeddings)
            
            # Distance to nearest cluster center
            distances = kmeans.transform(embeddings)
            min_distances = np.min(distances, axis=1) # Distance to assigned cluster center
            
            # Normalize outlier score (0-1)
            if np.max(min_distances) > 0:
                outlier_scores = min_distances / (np.max(min_distances) + 1e-9)
            else:
                outlier_scores = np.zeros(len(min_distances))

            # --- 3. Semantic Categorization (Zero-Shot Classification approximation) ---
            # Define category anchors
            categories = {
                "Authentication": "login logoff failure password credentials lock unlock",
                "Privilege": "elevate admin root sudo permission rights token",
                "Network": "connection firewall port ip address tcp udp http dns",
                "System": "service process cpu ram disk driver kernel boot shutdown",
                "File Access": "read write delete open modify file folder directory",
                "USB/Device": "usb device driver plug unplug storage media"
            }
            
            cat_names = list(categories.keys())
            cat_embeddings = self.model.encode(list(categories.values()))
            
            # Find closest category for each log
            # util.cos_sim returns (n_msgs, n_cats)
            cat_sims = util.cos_sim(embeddings, cat_embeddings).numpy()
            best_cat_indices = np.argmax(cat_sims, axis=1)
            predicted_categories = [cat_names[i] for i in best_cat_indices]


            # --- 4. Semantic Severity (Enhanced) ---
            danger_concepts = ["attack", "compromise", "unauthorized", "malicious", "failure", "critical", "denied", "exploit", "virus", "trojan"]
            danger_embedding = self.model.encode(" ".join(danger_concepts))
            severity_scores = util.cos_sim(embeddings, danger_embedding).numpy().flatten()
            
            # --- 5. PCA for Visualization (2D) ---
            from sklearn.decomposition import PCA
            pca = PCA(n_components=2)
            pca_result = pca.fit_transform(embeddings)
            
            df_out = pd.DataFrame({
                'timestamp': timestamps,
                'event_id': event_ids,
                'message': sampled_msgs,
                'source': df_sample['source'],
                'semantic_outlier_score': outlier_scores,
                'semantic_severity_score': severity_scores,
                'cluster_id': kmeans.labels_,
                'semantic_category': predicted_categories,
                'pca_x': pca_result[:, 0],
                'pca_y': pca_result[:, 1]
            })
            
            # Normalize severity for display
            df_out['semantic_severity_score'] = (df_out['semantic_severity_score'] - df_out['semantic_severity_score'].min()) / \
                                                (df_out['semantic_severity_score'].max() - df_out['semantic_severity_score'].min() + 1e-9)

            df_out = df_out.sort_values('semantic_outlier_score', ascending=False)
            df_out.to_csv(BERT_OUTPUT, index=False)
            print(f"Advanced BERT results (Clustering, PCA, & Categorization) saved to {BERT_OUTPUT}")
            
        except Exception as e:
            print(f"BERT Analysis failed: {e}")
            import traceback
            traceback.print_exc()

    def perform_tfidf_global(self, df):
        print("Starting Global TF-IDF Analysis...")
        msgs = df['message'].astype(str).tolist()
        if not msgs: return
        
        try:
            vectorizer = TfidfVectorizer(max_features=100, stop_words='english')
            tfidf_matrix = vectorizer.fit_transform(msgs)
            feature_names = vectorizer.get_feature_names_out()
            avg_scores = np.asarray(tfidf_matrix.mean(axis=0)).flatten().tolist()
            
            tfidf_df = pd.DataFrame({'keyword': feature_names, 'importance': avg_scores}).sort_values('importance', ascending=False)
            tfidf_df.to_csv(TF_OUTPUT, index=False)
        except ValueError:
            print("Not enough text data for TF-IDF.")

    def run_analysis(self):
        """Main entry point for the analysis pipeline"""
        df = self.load_data()
        if not df.empty:
            self.perform_threat_classification(df)
            self.perform_tfidf_global(df)
            self.perform_bert_advanced(df)
        else:
            print("No data found to analyze.")

if __name__ == "__main__":
    analyzer = SemanticAnalyzer()
    analyzer.run_analysis()
