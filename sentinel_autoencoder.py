
import torch
import torch.nn as nn
import torch.optim as optim
from sentence_transformers import SentenceTransformer
import numpy as np
import logging
import os
import joblib

# Configuration
TRAIN_FILE = "benign_traffic.txt"
MODEL_PATH = "sentinel_autoencoder.pth"
EMBEDDER_PATH = "sentinel_embedder.pkl" 
EMBEDDING_DIM = 384
HIDDEN_DIM = 128
LATENT_DIM = 64
EPOCHS = 50
BATCH_SIZE = 32
LR = 0.001

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SentinelBrain")

# --- 1. The Neural Network ---
class SentinelAutoencoder(nn.Module):
    def __init__(self):
        super(SentinelAutoencoder, self).__init__()
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(EMBEDDING_DIM, HIDDEN_DIM),
            nn.ReLU(),
            nn.Linear(HIDDEN_DIM, LATENT_DIM),
            nn.ReLU()
        )
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(LATENT_DIM, HIDDEN_DIM),
            nn.ReLU(),
            nn.Linear(HIDDEN_DIM, EMBEDDING_DIM),
            nn.Tanh() # Embeddings are normalized, but Tanh keeps it in -1 to 1 range approx.
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

def train_brain():
    if not os.path.exists(TRAIN_FILE):
        logger.error(f"Training data {TRAIN_FILE} not found!")
        return

    # --- 2. Data Prep ---
    logger.info("loading benign traffic...")
    with open(TRAIN_FILE, 'r') as f:
        requests = [line.strip() for line in f.readlines() if line.strip()]

    logger.info(f"Loaded {len(requests)} samples. Vectorizing via Transformer...")
    embedder = SentenceTransformer('all-MiniLM-L6-v2')
    embeddings = embedder.encode(requests)
    
    # Save Embedder for WAF to use
    joblib.dump(embedder, EMBEDDER_PATH)
    
    # Convert to Tensor
    data_tensor = torch.FloatTensor(embeddings)
    dataset = torch.utils.data.TensorDataset(data_tensor, data_tensor)
    dataloader = torch.utils.data.DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)

    # --- 3. Training Loop ---
    model = SentinelAutoencoder()
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=LR)

    logger.info("Igniting Neural Pathways (Training)...")
    model.train()
    for epoch in range(EPOCHS):
        total_loss = 0
        for batch in dataloader:
            inputs, targets = batch
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, targets)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        
        if (epoch+1) % 10 == 0:
            logger.info(f"Epoch [{epoch+1}/{EPOCHS}], Loss: {total_loss/len(dataloader):.6f}")

    # --- 4. Validation ---
    logger.info("Verifying Intelligence...")
    model.eval()
    
    # Test Benign
    benign_sample = data_tensor[0].unsqueeze(0)
    with torch.no_grad():
        recon_benign = model(benign_sample)
        loss_benign = criterion(recon_benign, benign_sample).item()
    
    # Test Anomaly
    attack_req = "POST /admin.php?cmd=cat%20/etc/passwd UNION SELECT 1"
    attack_emb = torch.FloatTensor(embedder.encode([attack_req]))
    with torch.no_grad():
        recon_attack = model(attack_emb)
        loss_attack = criterion(recon_attack, attack_emb).item()

    logger.info(f"Benign Reconstruction Error: {loss_benign:.6f}")
    logger.info(f"Attack Reconstruction Error: {loss_attack:.6f}")

    if loss_attack > loss_benign * 1.5:
        logger.info("SUCCESS: Anomaly detected with high confidence!")
    else:
        logger.warning("WARNING: Separation weak. More training data needed.")

    # --- 5. Save ---
    torch.save(model.state_dict(), MODEL_PATH)
    logger.info(f"Neural Weights saved to {MODEL_PATH}")

if __name__ == "__main__":
    train_brain()
