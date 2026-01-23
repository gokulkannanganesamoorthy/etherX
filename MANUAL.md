# EtherX Sentinel | Operator Playbook

## 1. System Overview

EtherX Sentinel acts as a **Sidecar Proxy** or **Reverse Proxy** in front of your web application. It intercepts 100% of HTTP traffic, analyzes it asynchronously, and enforces security policies based on AI inference.

## 2. Deployment Strategies

### A. Sidecar (Kubernetes)

Deploy EtherX as a sidecar container in your Pod.

- **Port Mapping**: Service -> EtherX (8000) -> Application (Localhost:3000)
- **Benefit**: Lowest latency (<2ms overhead).

### B. Gateway (Docker/VM)

Deploy EtherX as a centralized gateway.

- **Config**: Set `TARGET_URL` to your load balancer or internal service DNS.
- **Benefit**: Centralized management and logging.

## 3. Maintenance Procedures

### Model Retraining

As your application evolves (new APIs, new features), the Sentinel model must learn the new "Benign Patterns".

**Routine:**

1.  Collect 24h of **safe** access logs.
2.  Save to `benign_traffic.txt`.
3.  Run Training:
    ```bash
    python train_sentinel.py
    ```
4.  Restart WAF to load the new `sentinel_model.pkl`.

### troubleshooting

**Symptom: High False Positives (Blocking Safe Users)**

- **Cause**: Application changes (new routes) or overly aggressive Threshold.
- **Fix 1**: Retrain model with new traffic logs.
- **Fix 2**: Increase `BLOCK_THRESHOLD` env var to `30.0` (less sensitive).

**Symptom: Latency Spikes**

- **Cause**: CPU saturation during Embedding generation.
- **Fix**: Scale out WAF instances. The architecture is stateless.

## 4. Incident Response

When an attack is blocked (`BLOCK` action in logs):

1.  Query logs for `risk_details`.
2.  IP Ban the attacker at the firewall level if sustained.
3.  Analyze the `payload` in the JSON log to understand the attack vector.

---

**Emergency Bypass**
If the WAF malfunctions, route traffic directly to your backend service port (Bypass Port 8000).
