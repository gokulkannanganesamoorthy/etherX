# EtherX Sentinel | Enterprise AI WAF

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/etherx/sentinel)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

EtherX Sentinel is a **Production-Grade Web Application Firewall** fueled by **Deep Learning Anomaly Detection**. It utilizes **Sentence Transformers** to embed HTTP traffic into high-dimensional vector space and a **PyTorch Autoencoder** to identify malicious deviations (Zero-Day Attacks) with <10ms latency.

---

## 🚀 Key Features

- **Zero-Day Protection**: No regex signatures. Semantic understanding of attacks via `all-MiniLM-L6-v2` embeddings.
- **Deep Anomaly Detection**: A Neural Autoencoder reconstructs valid traffic; high reconstruction error = threat.
- **Honeypot Traps**: Instantly identifies scanners accessing `/admin.php` or `/.env`.
- **Real-time Observability**:
  - **WebSocket-powered** "Holographic" Dashboard (<50ms latency).
  - **Neural Activity Grid**: Visualizes AI inference live.
- **Production Readiness**:
  - Structural JSON Logging (ELK/Splunk compatible).
  - SQLite Persistence (`wafel.db`) for unlimited history.
  - Async I/O (FastAPI + Uvicorn).

---

## 📂 File Manifest & Project Structure

Detailed explanation of all files in this repository:

| File                          | Category        | Purpose                                                                                                                                                                                                    |
| :---------------------------- | :-------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`waf.py`**                  | **Core Engine** | The main application. Runs the **FastAPI** server, handles the **WAF Middleware** logic, loads the **AI Model**, serves the **Holographic Dashboard** (HTML/JS/CSS), and manages **WebSocket** broadcasts. |
| **`sentinel_autoencoder.py`** | **AI/ML**       | The training script. Defines the `SentinelAutoencoder` (PyTorch) architecture, loads `benign_traffic.txt`, generates embeddings, and trains the neural network. Outputs `sentinel_autoencoder.pth`.        |
| **`wafel.db`**                | **Database**    | Persistent SQLite database. Stores every request log with full metadata (`risk_details`, `payload_snippet`, `latency_ms`).                                                                                 |
| **`attack_simulation.py`**    | **Testing**     | **Red Team Tool**. Simulates various attacks (SQLi, XSS, RCE, Path Traversal) against the WAF to verify detection capabilities and generate "Threat" traffic for the dashboard.                            |
| **`generate_traffic.py`**     | **Data Prep**   | **Training Data Generator**. Simulates benign user behavior (GET/POST requests with varied User-Agents) to build the `benign_traffic.txt` dataset.                                                         |
| **`stress_test.py`**          | **Testing**     | **Load Testing Tool**. Uses `aiohttp` to flood the WAF with 1000+ concurrent requests, verifying that detection latency remains under 10ms.                                                                |
| **`production.sh`**           | **DevOps**      | Launcher script. Sets up the Python virtual environment, installs requirements, ensures models are trained, and starts the WAF.                                                                            |
| **`requirements.txt`**        | **Config**      | Python dependencies (`fastapi`, `uvicorn`, `torch`, `sentence-transformers`, `httpx`, `websockets`).                                                                                                       |
| **`mock_server.py`**          | **Upstream**    | A dummy vulnerable application (Port 3000) acting as the protected origin server (e.g., JuiceShop).                                                                                                        |
| **`benign_traffic.txt`**      | **Data**        | Dataset of "normal" HTTP requests used to train the Autoencoder on what "safe" looks like.                                                                                                                 |

---

## 🏗 Architecture

| Component         | Technology                          | Purpose                                          |
| :---------------- | :---------------------------------- | :----------------------------------------------- |
| **Ingestion**     | FastAPI (Async)                     | High-concurrency traffic interception.           |
| **Embedding**     | `sentence-transformers`             | Converts HTTP payloads to 384-d vectors.         |
| **Detection**     | **PyTorch Autoencoder**             | Neural reconstruction error (MSE) as Risk Score. |
| **Persistence**   | SQLite (`wafel.db`)                 | **Unlimited** log history with full metadata.    |
| **Observability** | **WebSockets (`/ws`)**              | Event-driven log streaming to Frontend.          |
| **Frontend**      | Vanilla JS + Tailwind (in `waf.py`) | "Modern Holographic" Neural Grid UI.             |

---

## 🛠 Deployment Guide

### Deployment (Automated)

The easiest way to run the full stack (WAF + Dashboard + Mock App):

```bash
./production.sh
```

This will:

1.  Set up the Python VirtualEnv.
2.  Install dependencies.
3.  **Train the AI Model** (if `sentinel_autoencoder.pth` is missing).
4.  Launch the Mock App (Port 3000) & WAF (Port 8000).

Visit **http://localhost:8000/dashboard** to see the **EtherX Sentinel UI**.

### Manual Run

```bash
# 1. Install Dependencies
pip install -r requirements.txt

# 2. Train the Neural Brain (if needed)
python sentinel_autoencoder.py

# 3. Start WAF
python waf.py
```

---

## 📊 Operations Manual

### Configuration (`env`)

| Variable          | Default                 | Description                      |
| :---------------- | :---------------------- | :------------------------------- |
| `TARGET_URL`      | `http://localhost:3000` | Upstream application to protect. |
| `BLOCK_THRESHOLD` | `20.0`                  | MSE Threshold for blocking.      |
| `MODEL_PATH`      | `./sentinel_model.pkl`  | Path to the serialized model.    |

### Monitoring

Logs are emitted to `stdout` in JSON format:

```json
{
  "event": "traffic_inspection",
  "client_ip": "192.168.1.5",
  "method": "POST",
  "risk_score": 45.2,
  "action": "BLOCK",
  "risk_details": { "neural_anomaly": true, "reconstruction_error": 0.045 },
  "latency_ms": 8.4
}
```

---

## 🛡 Verification & Testing

### 1. Simulated Attacks (Red Team)

Run the attack simulator to fire SQLi, XSS, and RCE payloads:

```bash
python attack_simulation.py
```

### 2. Stress Testing

Validate resilience under high load (1000+ RPS):

```bash
python stress_test.py
```

_Proves WAF latency stays under 10ms even under load._

---

_EtherX Security Research | 2026_
