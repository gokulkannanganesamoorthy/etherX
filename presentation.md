# EtherX Sentinel: Advanced AI WAF

**Team KADAVUL**
_Presenter: Gokul Kannan Ganesamoorthy_

---

## Slide 1: The Problem

### Why Legacy Firewalls Fail

- **Rule-Based Limitations**: Traditional WAFs rely on static Regex signatures.
- **The Zero-Day Threat**: Attackers constantly mutate payloads (e.g., `UN/**/ION SE/**/LECT`) to bypass filters.
- **Maintenance Nightmare**: Maintaining thousands of rules is inefficient and error-prone.
- **False Positives**: Strict rules often block legitimate user traffic.

---

## Slide 2: The Solution - EtherX Sentinel

### A Paradigm Shift in Security

**"Don't look for the attack. Look for the intention."**

- **Semantic Understanding**: Uses Natural Language Processing (NLP) to understand the _meaning_ of a request, not just its characters.
- **Behavioral Analysis**: Trained on "normal" traffic. Anything that deviates is automatically flagged as a threat.
- **No Signatures**: Detects 0-day XSS and SQLi attacks without a single Regex rule.

---

## Slide 3: The Deep Learning Engine

### How It Works

1.  **Ingestion**: High-speed traffic interception via **FastAPI**.
2.  **Embedding**: **Sentence Transformers** (`all-MiniLM-L6-v2`) convert text payloads into 384-dimensional vectors.
3.  **Neural Encoder**: A **PyTorch Autoencoder** compresses and reconstructs these vectors.
4.  **Anomaly Detection**:
    - Benign traffic reconstructs perfectly (Low Error).
    - Attack traffic fails to reconstruct (High Error).
    - **Result**: Instant BLOCK decision with <10ms inference latency.

---

---

## Slide 4: Technical Deep Dive

### Under the Hood

**1. The AI Model**

- **Architecture**: PyTorch Autoencoder (Compression/Decompression Network).
- **Embedding Layer**: `sentence-transformers` (**all-MiniLM-L6-v2**) converts HTTP payloads into a 384-dimensional vector space.
- **Training Data**: `benign_traffic.txt` (Only "safe" traffic). The model learns _normality_.

**2. The JSON Brain (Risk Analysis)**
Every request generates a detailed forensic report:

```json
{
  "risk_score": 85.4,
  "action": "BLOCK",
  "risk_details": {
    "neural_anomaly": true,
    "reconstruction_error": 0.04521,
    "signature_match": "union select"
  }
}
```

- **Reconstruction Error**: The "surprise" factor. High error (>0.02) means the model has never seen this pattern before (Zero-Day).

---

## Slide 5: The Training Pipeline

### Teaching the AI "Normality"

1.  **Data Generation** (`generate_traffic.py`):
    - We simulate thousands of **valid** user interactions (Logins, Searches, Browsing).
    - Result: `benign_traffic.txt` (Dataset of "Good Behavior").

2.  **Vectorization**:
    - Each request is converted into a list of numbers (Embedding).
    - _Example_: `"GET /login"` $\rightarrow$ `[0.1, -0.5, 0.8, ...]`

3.  **Self-Supervised Learning**:
    - The model forces itself to compress and decompress these vectors.
    - **Loss Function**: Mean Squared Error (MSE).
    - _Goal_: Make `Output` $\approx$ `Input` for all training data.

4.  **The Result**:
    - The model becomes an expert at reconstructing safe traffic.
    - When it sees an **Attack** (which it never studied), it fails to reconstruct it, triggering an alert.

---

## Slide 6: Key Innovations

- **Holographic Dashboard**: A real-time, WebSocket-powered "Neural Grid" UI that visualized the AI's decision-making process.
- **Live Threat Intel**: Active monitoring of SQLi, XSS, and Neural Anomalies.
- **Persistent Memory**: SQLite-backed behavioral logging for post-incident forensics.
- **Cyberpunk Aesthetics**: Designed for the modern security operations center (SOC).

---

## Slide 7: Architecture

_(Reference the Architecture Diagram in README)_

[Client] -> [Ingestion Layer] -> [AI Model] -> [Decision] -> [Dashboard]

- **Tech Stack**: Python, PyTorch, FastAPI, SQLite, Vanilla JS (Frontend).

---

## Slide 8: Live Demo

### What we will show

1.  **Normal Traffic**: Browsing the site (Allowed).
2.  **SQL Injection**: Attempting `OR 1=1` (Blocked by AI).
3.  **XSS Attack**: Trying `<script>` tags (Blocked).
4.  **Obfuscation**: Trying to bypass with complex encodings (Blocked by Semantic Analysis).
5.  **Dashboard**: Real-time visualization of these events.

---

## Slide 9: Conclusion

- **EtherX Sentinel** represents the future of adaptive application security.
- It learns, evolves, and protects without manual intervention.
- **Team KADAVUL** is proud to present this next-gen solution.

---

**Q&A**
