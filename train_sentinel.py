import sys
import os
import joblib
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.ensemble import IsolationForest
import logging

# Configuration
TRAIN_FILE = "benign_traffic.txt"
MODEL_PATH = "sentinel_model.pkl"
EMBEDDER_NAME = "all-MiniLM-L6-v2" # Fast and effective

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SentinelTrainer")

def train_sentinel():
    if not os.path.exists(TRAIN_FILE):
        logger.error(f"Training data {TRAIN_FILE} not found!")
        return

    logger.info(f"Loading data from {TRAIN_FILE}...")
    with open(TRAIN_FILE, 'r') as f:
        requests = [line.strip() for line in f.readlines() if line.strip()]

    logger.info(f"Loaded {len(requests)} requests. Initializing Embedder ({EMBEDDER_NAME})...")
    # This downloads the model if not present
    embedder = SentenceTransformer(EMBEDDER_NAME)
    
    logger.info("Generating Embeddings (This represents the semantic meaning of requests)...")
    embeddings = embedder.encode(requests, show_progress_bar=True)
    
    logger.info("Training Isolation Forest (The Anomaly Detector)...")
    # Contamination='auto' or very low because we assume training data is benign
    clf = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    clf.fit(embeddings)
    
    logger.info("Saving Sentinel Brain...")
    joblib.dump(clf, MODEL_PATH)
    logger.info(f"Model saved to {MODEL_PATH}")
    
    # Validation Test
    test_normal = requests[0]
    test_attack = "POST /search UNION SELECT * FROM users --"
    
    logger.info("--- Verification ---")
    vec_normal = embedder.encode([test_normal])
    vec_attack = embedder.encode([test_attack])
    
    # Isolation Forest returns 1 for inlier (normal), -1 for outlier (anomaly)
    # We want to convert this to a score. 
    # decision_function returns < 0 for anomaly, > 0 for normal
    
    score_normal = clf.decision_function(vec_normal)[0]
    score_attack = clf.decision_function(vec_attack)[0]
    
    logger.info(f"Normal Request Score: {score_normal:.4f} (Higher is better)")
    logger.info(f"Attack Request Score: {score_attack:.4f} (Lower = Anomaly)")
    
    if score_attack < score_normal:
        logger.info("SUCCESS: Attack scored lower than Normal.")
    else:
        logger.warning("WARNING: Attack was not clearly distinguished. Try more training data.")

if __name__ == "__main__":
    train_sentinel()
