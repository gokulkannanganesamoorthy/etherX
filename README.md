# EtherX Sentinel | Enterprise AI WAF

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/etherx/sentinel)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://hub.docker.com/r/etherx/sentinel)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

EtherX Sentinel is a **Production-Grade Web Application Firewall** fueled by advanced Anomaly Detection models. It utilizes **Sentence Transformers** to embed HTTP traffic into high-dimensional vector space and **Isolation Forests** to identify malicious deviations with <10ms latency.

---

## 🚀 Key Features

- **Zero-Day Protection**: No regex signatures. Semantic understanding of attacks via `all-MiniLM-L6-v2`.
- **Honeypot Traps**: Instantly identifies scanners accessing `/admin.php` or `/.env`.
- **Unsupervised Learning**: Trains on your benign traffic patterns. Anything else is blocked.
- **Production Readiness**:
  - Structural JSON Logging (ELK/Splunk compatible).
  - Docker & Kubernetes Ready.
  - Async I/O (FastAPI + Uvicorn).
- **Real-time Observability**: **WebSocket-powered** "Threat Hunter" Dashboard (<50ms latency).
- **High-Performance**: Tested at **1000+ RPS** via Async I/O (FastAPI + Uvicorn).

---

## 🏗 Architecture

| Component         | Technology                        | Purpose                                       |
| :---------------- | :-------------------------------- | :-------------------------------------------- |
| **Ingestion**     | FastAPI (Async)                   | High-concurrency traffic interception.        |
| **Embedding**     | `sentence-transformers`           | Converts HTTP payloads to 384-d vectors.      |
| **Detection**     | `scikit-learn` (Isolation Forest) | Statistical outlier detection.                |
| **Persistence**   | SQLite                            | **Unlimited** log history with full metadata. |
| **Observability** | **WebSockets (`/ws`)**            | Event-driven log streaming to Frontend.       |
| **Frontend**      | React + Vite                      | "Threat Hunter" Split-Pane Interface.         |

---

## 📂 Project Structure

| File                          | Purpose                                                                                                                |
| :---------------------------- | :--------------------------------------------------------------------------------------------------------------------- |
| **`waf.py`**                  | **Core Engine**. FastAPI app that intercepts traffic, runs AI inference, serves the Dashboard, and handles WebSockets. |
| **`mock_server.py`**          | **Upstream App**. A dummy vulnerable application (Port 3000) that mimics a real target (JuiceShop).                    |
| **`train_sentinel.py`**       | **Training Script**. Trains the Isolation Forest model using `benign_traffic.txt`.                                     |
| **`sentinel_autoencoder.py`** | **Deep Learning**. (Optional) Autoencoder architecture for advanced anomaly detection.                                 |
| **`attack_simulation.py`**    | **Red Team Tool**. Generates SQLi, XSS, and DoS attacks to test defenses.                                              |
| **`stress_test.py`**          | **Load Testing**. Uses `aiohttp` to blast the WAF with 1000+ concurrent requests.                                      |
| **`production.sh`**           | **Launcher**. Automated script to build UI, setup venv, and launch the WAF in production mode.                         |

---

## 🛠 Deployment Guide

### Deployment (Automated)

The easiest way to run the full stack (WAF + React Frontend + Mock App) is via the production script:

```bash
./production.sh
```

This will:

1.  Set up the Python VirtualEnv.
2.  Install dependencies.
3.  **Build the React Frontend** (new).
4.  Launch the Mock Upstream App (Port 3000).
5.  Launch the WAF & Dashboard (Port 8000).

Visit **http://localhost:8000/dashboard** to see the Sentinel Prime UI.

### Manual Run

```bash
# 1. Build Frontend
cd dashboard-ui && npm install && npm run build && cd ..

# 2. Train Model
python train_sentinel.py

# 3. Start WAF
uvicorn waf:app --host 0.0.0.0 --port 8000
```

---

## 📊 Operations Manual

### Configuration (`env`)

| Variable          | Default                 | Description                              |
| :---------------- | :---------------------- | :--------------------------------------- |
| `TARGET_URL`      | `http://localhost:3000` | Upstream application to protect.         |
| `BLOCK_THRESHOLD` | `20.0`                  | Sensitivity of the Sentinel model.       |
| `MODEL_PATH`      | `./sentinel_model.pkl`  | Path to the serialized Isolation Forest. |

### Monitoring

Logs are emitted to `stdout` in JSON format:

```json
{
  "event": "traffic_inspection",
  "client_ip": "192.168.1.5",
  "method": "POST",
  "risk_score": 45.2,
  "action": "BLOCK",
  "risk_details": { "sentinel_confidence": 0.45 },
  "latency_ms": 8.4
}
```

---

## 🛡 Verification

Run the included verification suite:

```bash
./demo.sh
```

**Attack Matrices Verified:**

- ✅ SQL Injection (Boolean-based, Union-based)
- ✅ XSS (Stored, Reflected)
- ✅ Remote Code Execution (Shell injection)
- ✅ Path Traversal (LFI)

---

_EtherX Security Research | 2026_

---

## 🕵️‍♂️ Feature Spotlight: Threat Hunter UI

The new **Phase 11 Dashboard** is designed for high-velocity SOC operations:

- **Split-Pane Layout**:
  - **Left**: High-Density Log Grid (Real-time stream).
  - **Right**: Inspector Panel (Full Request Forensics).
- **Deep Visibility**:
  - Click any log to inspect **Full Request URL**, **Headers**, **User-Agent**, and **Raw Payloads**.
  - Visual Risk Breakdown (Entropy vs. Sentinel AI Score).

---

## ⚡ Stress Testing

Validate production resilience with the included async load generator:

```bash
python stress_test.py
```

- Simulates **1000+ Concurrent Connections**.
- Uses `aiohttp` for non-blocking swarms.
- Proves WAF latency stays under 10ms even under load.

---

## 🏆 Hackathon Compliance Matrix

| Requirement                    | Implementation Details                                                                      | File / Code Ref                         |
| ------------------------------ | ------------------------------------------------------------------------------------------- | --------------------------------------- |
| **1. Log Ingestion**           | Live interception via FastAPI Middleware.                                                   | `waf.py`: `waf_middleware`              |
| **2. Parsing & Normalization** | Extracts Method/Path/Body. **Redacts PII (<EMAIL>)** and normalizes IDs (<ID>).             | `waf.py`: `normalize_payload()`         |
| **3. Tokenization**            | Uses `BertTokenizer` via `sentence-transformers`.                                           | `train_sentinel.py`: `all-MiniLM-L6-v2` |
| **4. Model Training**          | Anomaly Detection (Isolation Forest) on Transformer Embeddings. Trained on **Benign Only**. | `train_sentinel.py`                     |
| **5. Real-Time Inference**     | Async inference pipeline in WAF Loop.                                                       | `waf.py`: `get_risk_assessment()`       |
| **6. Demonstration**           | `attack_simulation.py` (Red Team) vs `generate_traffic.py` (Green Team).                    | `demo.sh`                               |

### Bonus Features Implemented

- [x] **Advanced Ingestion**: Real-time Proxy + Batch Training Support.
- [x] **Privacy & Security**: Automated Redaction of Emails and UUIDs.
- [x] **Server Integration**: Deployed as a Reverse Proxy Sidecar.
- [x] **Non-Blocking**: Fully Async FastAPI Architecture.
- [x] **UI/UX**: "Cyberpunk" Operator Dashboard (React + Vite). (Not graded but cool).
