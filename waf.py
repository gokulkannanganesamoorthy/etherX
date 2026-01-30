import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
import httpx
import logging
import sys
import time
import asyncio
import json
import os
import math
from collections import deque

# --- 1. Enterprise Configuration & Logging ---
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module
        }
        return json.dumps(log_entry)

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JsonFormatter())
logger = logging.getLogger("EtherX_Sentinel")
logger.setLevel(logging.INFO)
logger.handlers = [handler]

# Environment Variables
TARGET_URL = os.getenv("TARGET_URL", "http://localhost:3000")
MODEL_PATH = os.getenv("MODEL_PATH", "./sentinel_model.pkl")
THRESHOLD = float(os.getenv("BLOCK_THRESHOLD", "20.0"))

# State
# State (Initialized from DB later)
stats = {
    "total_requests": 0,
    "blocked_requests": 0,
    "allowed_requests": 0
}
recent_logs = deque(maxlen=20)

# --- 2. Model Loading (Sentinel Deep Brain) ---
embedder = None
autoencoder = None
model_threshold = 0.05 # MSE Threshold

try:
    import joblib
    import torch
    import torch.nn as nn
    from sentence_transformers import SentenceTransformer

    # Define Network Architecture (Must match training script)
    class SentinelAutoencoder(nn.Module):
        def __init__(self):
            super(SentinelAutoencoder, self).__init__()
            self.encoder = nn.Sequential(
                nn.Linear(384, 128),
                nn.ReLU(),
                nn.Linear(128, 64),
                nn.ReLU()
            )
            self.decoder = nn.Sequential(
                nn.Linear(64, 128),
                nn.ReLU(),
                nn.Linear(128, 384),
                nn.Tanh()
            )
        def forward(self, x):
            encoded = self.encoder(x)
            decoded = self.decoder(encoded)
            return decoded

    if os.path.exists("./sentinel_embedder.pkl") and os.path.exists("./sentinel_autoencoder.pth"):
        embedder = joblib.load("./sentinel_embedder.pkl")
        autoencoder = SentinelAutoencoder()
        autoencoder.load_state_dict(torch.load("./sentinel_autoencoder.pth"))
        autoencoder.eval() # Inference Mode
        logger.info(json.dumps({"event": "system_startup", "status": "SENTINEL_DEEP_BRAIN_ONLINE"}))
    else:
        logger.warning(json.dumps({"event": "system_startup", "status": "MOCK_MODE", "reason": "Deep Brain not found"}))
except Exception as e:
    logger.error(json.dumps({"event": "system_startup_error", "error": str(e)}))

# --- 4. Application Initialization (MOVED UP) ---
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import sqlite3

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = httpx.AsyncClient(base_url=TARGET_URL)

# --- 3. Persistence & Security ---
# Ensure absolute path for DB to avoid CWD issues
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wafel.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Create table with original schema if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  timestamp TEXT, 
                  method TEXT, 
                  path TEXT, 
                  score REAL, 
                  status TEXT, 
                  class TEXT,
                  client_ip TEXT)''')
    
    # Schema Migration: Add new columns if they don't exist
    c.execute("PRAGMA table_info(logs)")
    columns = [info[1] for info in c.fetchall()]
    
    start_cols = ["risk_details", "latency_ms", "user_agent", "payload_snippet"]
    col_types = ["TEXT", "REAL", "TEXT", "TEXT"]
    
    for col, col_type in zip(start_cols, col_types):
        if col not in columns:
            try:
                print(f"Migrating DB: Adding {col} column...")
                c.execute(f"ALTER TABLE logs ADD COLUMN {col} {col_type}")
            except Exception as e:
                print(f"Migration Error for {col}: {e}")

    conn.commit()
    conn.close()

init_db()

def load_stats_from_db():
    try:
        if not os.path.exists(DB_PATH):
            logger.warning(f"DB not found at {DB_PATH}, starting fresh.")
            return {"total_requests": 0, "blocked_requests": 0, "allowed_requests": 0}
            
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM logs")
        total = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM logs WHERE class='blocked'")
        blocked = c.fetchone()[0]
        conn.close()
        
        logger.info(f"Loaded Stats from DB: Total={total}, Blocked={blocked}")
        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "allowed_requests": total - blocked 
        }
    except Exception as e:
        logger.error(f"Stats Load Error: {e}")
        return {"total_requests": 0, "blocked_requests": 0, "allowed_requests": 0}

# Load persistent stats
stats = load_stats_from_db()

def log_to_db(log_entry):
    # We store full_url in risk_details to avoid schema migration for now
    if "full_url" in log_entry:
        if "risk_details" not in log_entry or not log_entry["risk_details"]:
            log_entry["risk_details"] = {}
        log_entry["risk_details"]["full_url"] = log_entry["full_url"]

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT INTO logs 
                     (timestamp, method, path, score, class, status, client_ip, risk_details, latency_ms, user_agent, payload_snippet)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (log_entry['time'], log_entry['method'], log_entry['path'], 
                   float(log_entry['score']), log_entry['class'], log_entry['status'], 
                   log_entry['client_ip'], json.dumps(log_entry['risk_details']), 
                   log_entry['latency_ms'], log_entry['user_agent'], log_entry['payload_snippet']))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"DB Error: {e}")

class TokenBucket:
    def __init__(self, rate=100, per=60):
        self.rate = rate
        self.per = per
        self.tokens = {}
        
    def allow(self, ip):
        now = time.time()
        if ip not in self.tokens:
            self.tokens[ip] = {"tokens": self.rate, "last": now}
        
        bucket = self.tokens[ip]
        elapsed = now - bucket["last"]
        bucket["tokens"] += elapsed * (self.rate / self.per)
        if bucket["tokens"] > self.rate: bucket["tokens"] = self.rate
        bucket["last"] = now
        
        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            return True
        return False

rate_limiter = TokenBucket(rate=100, per=60) # 100 req/min per IP

import re

def normalize_payload(text):
    """
    Normalization & Privacy Masking (Bonus Requirement):
    1. Replace UUIDs with <UUID>
    2. Replace Emails with <EMAIL> (Privacy)
    3. Replace Timestamps/Numbers with <ID>
    """
    if not text: return ""
    
    # URL Decode
    from urllib.parse import unquote
    text = unquote(text).lower()
    
    # 1. Mask Emails (Privacy)
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '<EMAIL>', text)
    
    # 2. Mask UUIDs
    text = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<UUID>', text)
    
    # 3. Mask Numbers (IDs, Timestamps)
    text = re.sub(r'\d+', '<ID>', text)
    
    return text

def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x)))/len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def get_risk_assessment(raw_text):
    """
    Performs a multi-layered risk assessment:
    1. Sentinel Deep Autoencoder (Reconstruction Error) - Primary
    2. Statistical Entropy Analysis - Secondary
    3. Keyword Heuristics - Fallback/Context
    """
    risk_score = 0.0
    details = {}
    
    # Preprocess: Normalize & Redact
    normalized_text = normalize_payload(raw_text)
    
    # Layer 1: Sentinel Deep Learning
    if embedder and autoencoder:
        try:
            # Inference 
            with torch.no_grad():
                # 1. Embed
                vector = embedder.encode([normalized_text])
                tensor_in = torch.FloatTensor(vector)
                
                # 2. Reconstruct
                reconstruction = autoencoder(tensor_in)
                
                # 3. Calculate Error (MSE)
                mse_loss = torch.mean((tensor_in - reconstruction) ** 2).item()
                
                # 4. Map to Risk Score
                # Typical benign MSE is ~0.005. Attacks are > 0.02
                # We scale this to 0-100
                if mse_loss > model_threshold:
                    sentinel_risk = min(100, (mse_loss / model_threshold) * 50)
                    risk_score += sentinel_risk
                    details['neural_anomaly'] = True
                    details['reconstruction_error'] = round(mse_loss, 5)
                else:
                    details['neural_confidence'] = "SAFE"
                    
        except Exception as e:
            logger.error(json.dumps({"event": "inference_error", "error": str(e)}))

    # Layer 2: Entropy (Obfuscation Detection)
    entropy = calculate_entropy(raw_text)
    if entropy > 4.5:
        risk_score += 15 * (entropy - 4.0)
        details['high_entropy'] = True

    # Layer 3: Known Signatures (Contextual Weights)
    text_lower = normalized_text
    
    img_tags = [
        "<script>", "union select", "eval(", "javax.naming", "/etc/passwd", 
        "alert(1)", "javascript:", "or 1=1", "admin' --", "union all select"
    ]
    for tag in img_tags:
        if tag in text_lower:
            risk_score += 50.0
            details['signature_match'] = tag

    return max(1.0, risk_score), details

# --- 4.5. Realtime WebSocket Manager ---
from fastapi import WebSocket, WebSocketDisconnect

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text() # Keep alive
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# --- 5. Alerting & Broadcasting ---
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")

async def send_alert(payload):
    # 1. Async Webhook (Slack/Discord)
    if WEBHOOK_URL:
        try:
            async with httpx.AsyncClient() as client:
                message = {
                    "content": f"🚨 **ETHERX SECURITY ALERT** 🚨\n\n**IP:** {payload['client_ip']}\n**Path:** `{payload['path']}`\n**Risk Score:** {payload['risk_score']}\n**Reason:** {json.dumps(payload['risk_details'])}"
                }
                await client.post(WEBHOOK_URL, json=message)
        except Exception as e:
            logger.error(f"Alert Error: {e}")

    # 2. WebSocket Broadcast (Dashboard)
    # We broadcast the full log object expected by frontend
    ws_payload = json.dumps({
        "type": "new_log",
        "data": {
            "time": time.strftime("%H:%M:%S"),
            "method": payload['method'],
            "path": payload['path'],
            "full_url": payload.get('full_url', payload['path']),
            "score": payload['risk_score'],
            "status": payload['action'],
            "class": "blocked" if payload['action'] == "BLOCK" else "allowed",
            "risk_details": payload['risk_details'],
            "latency_ms": payload['latency_ms'],
            "client_ip": payload['client_ip'],
            "user_agent": payload.get('user_agent'),
            "payload": payload.get('payload_snippet')
        },
        "stats": stats
    })
    await manager.broadcast(ws_payload)

# --- 5. WAF Middleware ---
@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    # Bypass WAF for Dashboard, Stats, and Static Assets
    if request.url.path.startswith("/assets") or request.url.path in ["/", "/dashboard", "/stats", "/favicon.ico", "/vite.svg", "/ws"]: 
        return await call_next(request)

    start_time = time.time()
    client_ip = request.client.host
    
    # 1. Rate Limiting (DoS Protection)
    if not rate_limiter.allow(client_ip):
        stats["blocked_requests"] += 1
        logger.warning(json.dumps({"event": "security_alert", "type": "DoS_attempt", "ip": client_ip, "action": "DROP"}))
        return Response("Too Many Requests", status_code=429)

    method = request.method
    path = request.url.path
    query = request.url.query
    
    try:
        body_bytes = await request.body()
        body_str = body_bytes.decode('utf-8', errors='ignore')
    except:
        body_str = ""
        body_bytes = b""
        
    full_payload = f"{method} {path} {query} {body_str}"
    
    # --- HONEYPOT TRAP (Bonus Feature) ---
    HONEYPOT_PATHS = ["/admin.php", "/.env", "/config.php", "/backup.sql", "/api/v1/secret"]
    is_honeypot = any(path.startswith(hp) for hp in HONEYPOT_PATHS)
    
    if is_honeypot:
        score = 100.0
        risk_details = {"honeypot_triggered": True, "trap": path}
        is_blocked = True
        logger.warning(json.dumps({"event": "honeypot_trap", "ip": client_ip, "trap": path}))
    else:
        # Risk Analysis
        score, risk_details = get_risk_assessment(full_payload)
        is_blocked = score > THRESHOLD
    
    # Metrics
    duration = time.time() - start_time
    stats["total_requests"] += 1
    
    log_payload = {
        "event": "traffic_inspection",
        "client_ip": client_ip,
        "method": method,
        "path": path,
        "full_url": str(request.url),
        "query": query,
        "user_agent": request.headers.get("user-agent", "unknown"),
        "payload_snippet": body_str[:200] if body_str else None,
        "risk_score": round(score, 4),
        "action": "BLOCK" if is_blocked else "ALLOW",
        "risk_details": risk_details,
        "latency_ms": round(duration * 1000, 2)
    }
    

    log_entry = {
        "time": time.strftime("%H:%M:%S"),
        "method": method,
        "path": path,
        "full_url": str(request.url),
        "score": f"{score:.2f}",
        "class": "blocked" if is_blocked else "allowed",
        "status": "BLOCKED" if is_blocked else "ALLOWED",
        "client_ip": client_ip,
        "risk_details": risk_details,
        "latency_ms": round(duration * 1000, 2),
        "user_agent": request.headers.get("user-agent", "unknown"),
        "payload_snippet": body_str[:200] if body_str else None
    }
    
    # Persistence
    log_to_db(log_entry)
    
    if is_blocked:
        stats["blocked_requests"] += 1
        logger.warning(json.dumps(log_payload))
        # Alerting (Async Webhook)
        asyncio.create_task(send_alert(log_payload)) 
        
        return Response(
            content=json.dumps({"error": "EtherX Security Block", "request_id": str(time.time())}), 
            status_code=403, 
            media_type="application/json"
        )
    else:
        stats["allowed_requests"] += 1
        logger.info(json.dumps(log_payload))
        # Broadcast Allowed requests too for Realtime Feed
        asyncio.create_task(send_alert(log_payload))

    # Forwarding
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)
    
    try:
        url = f"{path}?{query}" if query else path
        proxy_resp = await client.request(method, url, headers=headers, content=body_bytes, cookies=request.cookies)
        return Response(content=proxy_resp.content, status_code=proxy_resp.status_code, headers=proxy_resp.headers, media_type=proxy_resp.headers.get('content-type'))
    except httpx.RequestError as e:
        logger.error(json.dumps({"event": "upstream_error", "error": str(e)}))
        return Response("Upstream Gateway Error", status_code=502)

# Fallback for API Stats
@app.get("/stats")
async def get_stats():
    """API Endpoint for Real-Time Dashboard Data"""
    # Fetch all logs from DB
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Access columns by name
    c = conn.cursor()
    
    # Removed LIMIT 20 to show all requests
    c.execute("SELECT * FROM logs ORDER BY id DESC")
    rows = c.fetchall()
    
    db_logs = []
    for r in rows:
        try:
            risk_details = json.loads(r["risk_details"]) if r["risk_details"] else {}
        except:
            risk_details = {}
            
        db_logs.append({
            "id": r["id"],
            "time": r["timestamp"],
            "method": r["method"],
            "path": r["path"],
            "full_url": risk_details.get("full_url", r["path"]),
            "score": r["score"],
            "status": r["status"],
            "class": r["class"],
            "client_ip": r["client_ip"],
            "risk_details": risk_details,
            "latency_ms": r["latency_ms"],
            "user_agent": r["user_agent"],
            "payload_snippet": r["payload_snippet"]
        })
        
    conn.close()
    
    return {
        "stats": stats,
        "logs": db_logs,
        "system_status": "ONLINE",
        "model": "SENTINEL-L6" if embedder else "DISTILBERT (MOCK)"
    }

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>ETHERX | SENTINEL PRIME</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
        <script>
            tailwind.config = {
                theme: {
                    extend: {
                        fontFamily: { 
                            sans: ['"Outfit"', 'sans-serif'],
                            mono: ['"JetBrains Mono"', 'monospace'] 
                        },
                        colors: {
                            'holo-bg': '#050b14',
                            'holo-card': 'rgba(15, 23, 42, 0.6)',
                            'holo-cyan': '#00f3ff',
                            'holo-purple': '#bc13fe',
                            'holo-green': '#00ff9d',
                            'holo-red': '#ff0055',
                        },
                        backgroundImage: {
                            'cyber-grid': "linear-gradient(rgba(0, 243, 255, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 243, 255, 0.03) 1px, transparent 1px)",
                            'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
                        },
                        animation: {
                            'spin-slow': 'spin 12s linear infinite',
                            'float': 'float 6s ease-in-out infinite',
                            'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                        },
                        keyframes: {
                            float: {
                                '0%, 100%': { transform: 'translateY(0)' },
                                '50%': { transform: 'translateY(-10px)' },
                            }
                        }
                    }
                }
            }
        </script>
        <style>
             body { 
                 background-color: #030712; 
                 background-image: 
                    radial-gradient(circle at 50% 0%, rgba(188, 19, 254, 0.15) 0%, transparent 50%),
                    radial-gradient(circle at 100% 0%, rgba(0, 243, 255, 0.1) 0%, transparent 40%);
                 color: #e2e8f0; 
                 font-family: 'Outfit', sans-serif;
             }
             
             .bg-grid {
                 background-size: 50px 50px;
                 mask-image: linear-gradient(to bottom, transparent, 2%, white, 90%, transparent);
             }

             /* Glass Panel */
             .glass-panel {
                 background: rgba(10, 15, 30, 0.6);
                 backdrop-filter: blur(16px);
                 -webkit-backdrop-filter: blur(16px);
                 border: 1px solid rgba(255, 255, 255, 0.08);
                 box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
             }
             
             /* Custom Scrollbar */
             ::-webkit-scrollbar { width: 6px; }
             ::-webkit-scrollbar-track { background: transparent; }
             ::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.1); border-radius: 10px; }
             ::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.2); }

             /* Utility Classes */
             .text-cyan-glow { text-shadow: 0 0 10px rgba(0, 243, 255, 0.5); }
             .text-purple-glow { text-shadow: 0 0 10px rgba(188, 19, 254, 0.5); }
             .border-gradient { border-image: linear-gradient(to right, #00f3ff, #bc13fe) 1; }
             
             /* Neural Grid */
             .neural-grid-container {
                 display: grid;
                 grid-template-columns: repeat(8, 1fr);
                 gap: 4px;
                 width: 160px;
                 transform: rotate(45deg);
             }
             .neuron {
                 width: 12px;
                 height: 12px;
                 background: rgba(255, 255, 255, 0.03);
                 border: 1px solid rgba(0, 243, 255, 0.1);
                 transition: all 0.2s ease;
             }
             .neuron.active {
                 background: #00f3ff;
                 box-shadow: 0 0 8px #00f3ff;
                 border-color: #fff;
             }
             .neuron.active-red {
                 background: #ff0055;
                 box-shadow: 0 0 8px #ff0055;
                 border-color: #fff;
             }

             /* Animations */
             .animate-pulse-glow { animation: pulse-glow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
             @keyframes pulse-glow {
                 0%, 100% { opacity: 1; filter: drop-shadow(0 0 5px rgba(0, 243, 255, 0.7)); }
                 50% { opacity: .5; filter: drop-shadow(0 0 2px rgba(0, 243, 255, 0.3)); }
             }

             /* Tutorial Styles */
             #tutorial-overlay { transition: opacity 0.5s ease; }
             .tutorial-highlight { 
                 position: relative; 
                 z-index: 60; 
                 box-shadow: 0 0 0 9999px rgba(0, 0, 0, 0.85); 
                 border-radius: 12px;
                 pointer-events: none;
             }
             .tutorial-box {
                 position: fixed;
                 z-index: 70;
                 width: 320px;
                 opacity: 0;
                 transform: translateY(10px);
                 transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
             }
             .tutorial-box.visible { opacity: 1; transform: translateY(0); }
        </style>
    </head>
    <body class="h-screen flex flex-col overflow-hidden selection:bg-holo-cyan selection:text-black">
        
        <!-- Background Grid -->
        <div class="fixed inset-0 bg-cyber-grid bg-grid opacity-20 pointer-events-none z-0"></div>

        <!-- Navbar -->
        <nav class="border-b border-white/5 bg-black/20 backdrop-blur-md z-40" id="header-section">
            <div class="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
                <div class="flex items-center gap-4">
                     <div class="relative group">
                        <div class="absolute -inset-1 bg-gradient-to-r from-holo-cyan to-holo-purple rounded-lg blur opacity-40 group-hover:opacity-75 transition duration-500"></div>
                        <div class="relative h-10 w-10 bg-black rounded-lg flex items-center justify-center border border-white/10">
                            <span class="font-bold text-white text-xl">E</span>
                        </div>
                     </div>
                     <div class="flex flex-col">
                        <h1 class="text-xl font-bold tracking-wide text-white uppercase font-sans">EtherX <span class="font-light text-white/50">Sentinel</span></h1>
                        <span class="text-[10px] uppercase tracking-[0.2em] text-holo-cyan text-cyan-glow">Advanced Security Protocol</span>
                     </div>
                </div>
                <div class="flex items-center gap-6">
                     <div class="flex items-center gap-2 px-3 py-1 rounded-full bg-holo-cyan/5 border border-holo-cyan/20">
                        <div class="h-2 w-2 bg-holo-cyan rounded-full animate-pulse-glow"></div>
                        <span class="text-xs font-medium text-holo-cyan tracking-wider uppercase">System Active</span>
                     </div>

                     <button onclick="startTutorial()" class="p-2 rounded hover:bg-white/5 text-holo-cyan transition-colors" title="Start Tutorial">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                     </button>
                     <span class="font-mono text-xs text-white/30">V.11.0.4</span>
                </div>
            </div>
        </nav>

        <!-- Main Content -->
        <main class="relative flex-1 max-w-7xl mx-auto w-full p-6 grid grid-cols-1 lg:grid-cols-12 gap-8 min-h-0 z-10">
            
            <!-- Left Panel -->
            <div class="lg:col-span-4 flex flex-col gap-6">
                
                <!-- THREAT INTELLIGENCE CARD -->
                <div class="glass-panel rounded-2xl p-6 relative flex flex-col overflow-hidden min-h-[300px]" id="threat-panel">
                    <div class="flex justify-between items-start mb-6">
                         <div>
                            <h3 class="text-sm font-bold text-white tracking-widest uppercase">Threat Intel</h3>
                            <span class="text-[10px] uppercase tracking-widest text-holo-cyan" id="ti-status">Active Monitoring</span>
                         </div>
                         <div class="px-2 py-1 rounded bg-holo-cyan/10 border border-holo-cyan/20 text-[10px] font-mono text-holo-cyan animate-pulse">LIVE</div>
                    </div>

                    <!-- Threat Breakdown -->
                    <div class="flex-1 flex flex-col justify-center gap-4" id="threat-intel-body">
                         <div class="space-y-4">
                             <!-- SQL Injection -->
                             <div>
                                 <div class="flex justify-between items-center text-[10px] uppercase tracking-wider mb-1">
                                     <span class="text-white/60">SQL Injection</span>
                                     <span class="font-mono text-holo-red font-bold" id="val-sqli">0</span>
                                 </div>
                                 <div class="h-1.5 bg-white/5 rounded-full overflow-hidden">
                                     <div class="h-full bg-holo-red w-[0%] transition-all duration-1000" id="bar-sqli"></div>
                                 </div>
                             </div>
                             
                             <!-- XSS -->
                             <div>
                                 <div class="flex justify-between items-center text-[10px] uppercase tracking-wider mb-1">
                                     <span class="text-white/60">XSS / Scripting</span>
                                     <span class="font-mono text-holo-purple font-bold" id="val-xss">0</span>
                                 </div>
                                 <div class="h-1.5 bg-white/5 rounded-full overflow-hidden">
                                     <div class="h-full bg-holo-purple w-[0%] transition-all duration-1000" id="bar-xss"></div>
                                 </div>
                             </div>

                             <!-- Anomaly/Other -->
                             <div>
                                 <div class="flex justify-between items-center text-[10px] uppercase tracking-wider mb-1">
                                     <span class="text-white/60">Neural Anomalies</span>
                                     <span class="font-mono text-holo-cyan font-bold" id="val-anomaly">0</span>
                                 </div>
                                 <div class="h-1.5 bg-white/5 rounded-full overflow-hidden">
                                     <div class="h-full bg-holo-cyan w-[0%] transition-all duration-1000" id="bar-anomaly"></div>
                                 </div>
                             </div>
                         </div>
                    </div>
                    
                    <!-- Decorator -->
                    <div class="absolute bottom-0 right-0 p-4 opacity-20 pointer-events-none">
                         <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" class="text-holo-cyan">
                            <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"></path>
                         </svg>
                    </div>
                </div>

                <!-- Stats Grid -->
                <div class="grid grid-cols-2 gap-4" id="stats-grid">
                     <div class="glass-panel rounded-2xl p-5 hover:bg-white/5 transition-colors group">
                         <div class="text-xs font-bold text-white/40 uppercase mb-2 group-hover:text-white/60 transition-colors">Total Traffic</div>
                         <div class="text-3xl font-bold text-white tracking-tight font-mono" id="total-req">0</div>
                     </div>
                     <div class="glass-panel rounded-2xl p-5 hover:bg-white/5 transition-colors group">
                         <div class="text-xs font-bold text-white/40 uppercase mb-2 group-hover:text-white/60 transition-colors">Latency</div>
                         <div class="flex items-baseline gap-1">
                             <div class="text-3xl font-bold text-holo-cyan tracking-tight font-mono" id="latency">0</div>
                             <div class="text-sm font-medium text-holo-cyan/50">ms</div>
                         </div>
                     </div>
                     <div class="glass-panel rounded-2xl p-5 relative overflow-hidden group">
                         <div class="absolute bottom-0 left-0 w-full h-1 bg-gradient-to-r from-holo-green to-transparent opacity-50 group-hover:opacity-100 transition-opacity"></div>
                         <div class="text-xs font-bold text-holo-green/60 uppercase mb-2">Allowed</div>
                         <div class="text-3xl font-bold text-white tracking-tight font-mono" id="allowed-req">0</div>
                     </div>
                     <div id="blocked-card" class="glass-panel rounded-2xl p-5 relative overflow-hidden group">
                         <div class="absolute bottom-0 left-0 w-full h-1 bg-gradient-to-r from-holo-red to-transparent opacity-50 group-hover:opacity-100 transition-opacity"></div>
                         <div class="text-xs font-bold text-holo-red/60 uppercase mb-2">Threats</div>
                         <div class="text-3xl font-bold text-white tracking-tight font-mono" id="blocked-req">0</div>
                     </div>
                </div>
            </div>

            <!-- Right Panel: Feed -->
            <div class="lg:col-span-8 flex flex-col h-full min-h-0" id="feed-panel">
                <div class="glass-panel rounded-2xl flex-1 flex flex-col overflow-hidden">
                    <div class="p-5 border-b border-white/5 flex justify-between items-center bg-white/5 backdrop-blur-xl">
                        <div class="flex items-center gap-3">
                             <span class="flex h-2 w-2 relative">
                                <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-holo-green opacity-75"></span>
                                <span class="relative inline-flex rounded-full h-2 w-2 bg-holo-green"></span>
                              </span>
                            <h3 class="font-bold text-sm tracking-widest text-white uppercase">Live Inspection Feed</h3>
                        </div>
                        <div class="px-3 py-1 rounded-md bg-black/40 border border-white/10 text-[10px] font-mono text-white/50" id="model-name">SENTINEL-L6</div>
                    </div>
                    
                    <div class="flex-1 overflow-auto p-2 scroll-smooth">
                        <table class="w-full text-left border-collapse">
                            <thead class="text-[10px] text-white/30 uppercase tracking-wider sticky top-0 z-10 font-bold border-b border-white/5 bg-[#0a0f1e]">
                                <tr>
                                    <th class="p-4 font-medium">Time</th>
                                    <th class="p-4 font-medium">Method</th>
                                    <th class="p-4 font-medium w-96">Request Flow</th>
                                    <th class="p-4 text-right font-medium">Risk Score</th>
                                    <th class="p-4 text-right font-medium">Status</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-white/5 text-sm" id="log-table">
                                <!-- Dynamic Rows -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </main>

        <script>
            // WebSocket Connection
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws`;
            let socket;
            
            // Threat Intel Stats
            let threatStats = { sqli: 0, xss: 0, anomaly: 0 };
            
            function countThreat(log) {
                if(log.class !== 'blocked') return;
                const details = log.risk_details || {};
                let type = 'anomaly';
                
                // Heuristics
                const payload = (log.payload_snippet || "").toLowerCase();
                if (payload.includes('union') || payload.includes('select') || payload.includes('or 1=1')) type = 'sqli';
                
                if (details.signature_match) {
                     const sig = details.signature_match.toLowerCase();
                     if (sig.includes('script') || sig.includes('alert') || sig.includes('javascript')) type = 'xss';
                     else if (sig.includes('union') || sig.includes('select')) type = 'sqli';
                }
                
                if (type === 'sqli') threatStats.sqli++;
                else if (type === 'xss') threatStats.xss++;
                else threatStats.anomaly++;
            }
            
            function updateThreatVisuals() {
                const total = threatStats.sqli + threatStats.xss + threatStats.anomaly;
                ['sqli', 'xss', 'anomaly'].forEach(key => {
                    const valEl = document.getElementById(`val-${key}`);
                    const barEl = document.getElementById(`bar-${key}`);
                    if(valEl) valEl.innerText = threatStats[key];
                    
                    if(barEl && total > 0) {
                        const pct = (threatStats[key] / total) * 100;
                        barEl.style.width = `${pct}%`;
                    }
                });
            }

            function connectWebSocket() {
                // Check if socket exists and is active
                if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
                    return; 
                }
                  
                if (!socket || (socket.readyState !== WebSocket.OPEN && socket.readyState !== WebSocket.CONNECTING)) {
                    socket = new WebSocket(wsUrl);

                    socket.onopen = function() {
                        console.log("Connected to Real-time Feed");
                        const modelEl = document.getElementById('model-name');
                        if (modelEl && !modelEl.innerText.includes("LIVE")) modelEl.innerText += " • LIVE";
                    };

                    socket.onmessage = function(event) {
                        try {
                            const msg = JSON.parse(event.data);
                            if (msg.type === 'new_log') {
                                updateDashboard(msg.data, msg.stats);
                            }
                        } catch(e) { console.error("WS Message Error", e); }
                    };

                    socket.onclose = function() {
                        console.log("Disconnected. Reconnecting...");
                        setTimeout(connectWebSocket, 3000);
                    };
                    
                    socket.onerror = function(err) {
                        console.error("WebSocket Error", err);
                    };
                }
            }

            function getMethodColor(method) {
                switch(method) {
                    case 'GET': return 'text-holo-cyan';
                    case 'POST': return 'text-holo-purple';
                    case 'DELETE': return 'text-holo-red';
                    default: return 'text-white/50';
                }
            }

            function updateDashboard(log, stats) {
                // 1. Update Stats
                if (stats) {
                    document.getElementById('total-req').innerText = stats.total_requests.toLocaleString();
                    document.getElementById('allowed-req').innerText = stats.allowed_requests.toLocaleString();
                    document.getElementById('blocked-req').innerText = stats.blocked_requests.toLocaleString();
                }
                
                // 2. Update Visuals
                const isBlocked = log.class === 'blocked';
                const blockedCard = document.getElementById('blocked-card');
                
                if (isBlocked) {
                    // Flash Effect
                    document.body.style.boxShadow = "inset 0 0 100px rgba(255, 0, 85, 0.2)";
                    setTimeout(() => document.body.style.boxShadow = "none", 300);
                    
                    if (blockedCard) {
                        blockedCard.classList.add('ring-1', 'ring-holo-red');
                        setTimeout(() => blockedCard.classList.remove('ring-1', 'ring-holo-red'), 2500);
                    }
                    
                    // Update Threat Intel
                    countThreat(log);
                    updateThreatVisuals();
                }

                // 3. Add to Table
                try {
                    const tbody = document.getElementById('log-table');
                    const methodColor = getMethodColor(log.method);
                    const rowId = log.id || Math.random().toString(36).substr(2, 9);
    
                    const tr = document.createElement('tr');
                    tr.className = `group cursor-pointer hover:bg-white/5 transition-all duration-300 font-mono ${isBlocked ? 'bg-red-500/5 hover:bg-red-500/10' : 'hover:bg-cyan-500/5'}`;
                    tr.onclick = () => toggleDetails(rowId);
                    
                    const statusPill = isBlocked 
                        ? `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-red-400/10 text-red-400 border border-red-400/20 shadow-[0_0_10px_rgba(248,113,113,0.1)]">DENIED</span>`
                        : `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-400/10 text-emerald-400 border border-emerald-400/20">ALLOWED</span>`;
    
                    // Safely handle full_url and other fields
                    const fullUrl = log.risk_details && log.risk_details.full_url ? log.risk_details.full_url : (log.full_url || log.path);
                    const displayPath = fullUrl || log.path;

                    tr.innerHTML = `
                        <td class="p-4 text-white/60 text-xs">${log.time || 'NOW'}</td>
                        <td class="p-4"><span class="${methodColor} font-bold text-xs">${log.method}</span></td>
                        <td class="p-4 text-xs group-hover:text-white transition-colors">
                            <div class="flex flex-col gap-1">
                                <div class="flex items-center gap-2 text-[10px] text-white/40 font-mono">
                                    <span>${log.client_ip}</span>
                                    <span class="text-holo-cyan">➜</span>
                                    <span>SERVER</span>
                                </div>
                                <div class="font-mono text-white/90 truncate w-96" title="${displayPath}">${displayPath}</div>
                            </div>
                        </td>
                        <td class="p-4 text-right text-xs font-bold text-white/80">${log.score}</td>
                        <td class="p-4 text-right">
                            ${statusPill}
                        </td>
                    `;
                    
                    const detailTr = document.createElement('tr');
                    detailTr.id = `detail-${rowId}`;
                    detailTr.className = "hidden bg-black/20";
                    const detailsJson = JSON.stringify(log.risk_details || {}, null, 2);
                    
                    detailTr.innerHTML = `
                        <td colspan="5" class="p-0">
                             <div class="m-2 rounded-lg bg-black/40 border border-white/5 p-4 text-xs">
                                <div class="grid grid-cols-3 gap-6 mb-4 pb-4 border-b border-white/5">
                                     <div><span class="block text-white/30 uppercase text-[10px] tracking-widest mb-1">Source IP</span><span class="font-mono text-white">${log.client_ip}</span></div>
                                     <div><span class="block text-white/30 uppercase text-[10px] tracking-widest mb-1">Latency</span><span class="font-mono text-white">${log.latency_ms}ms</span></div>
                                     <div class="truncate"><span class="block text-white/30 uppercase text-[10px] tracking-widest mb-1">User Agent</span><span class="font-mono text-white/70 truncate block" title="${log.user_agent}">${log.user_agent || 'UNKNOWN'}</span></div>
                                </div>
                                 ${log.payload_snippet ? `<div class="mb-4"><div class="text-holo-cyan text-[10px] uppercase tracking-widest mb-2 font-bold">Payload Dump</div><div class="bg-black/50 border border-white/10 p-3 rounded font-mono text-white/70 break-all select-all">${log.payload_snippet.replace(/</g, '&lt;')}</div></div>` : ''}
                                <div><div class="text-holo-purple text-[10px] uppercase tracking-widest mb-2 font-bold">Risk Analysis</div><pre class="font-mono text-white/60 whitespace-pre-wrap text-[10px]">${detailsJson}</pre></div>
                            </div>
                        </td>
                    `;
    
                    tr.style.opacity = '0';
                    tr.style.transform = 'translateY(-10px)';
                    tbody.insertBefore(detailTr, tbody.firstChild);
                    tbody.insertBefore(tr, tbody.firstChild);
                    requestAnimationFrame(() => {
                        tr.style.opacity = '1';
                        tr.style.transform = 'translateY(0)';
                    });
                    
                    if (tbody.children.length > 50) {
                        tbody.removeChild(tbody.lastChild);
                        tbody.removeChild(tbody.lastChild);
                    }
                } catch(e) { console.error("Update Dashboard Error", e); }
            }

            function toggleDetails(id) {
                const el = document.getElementById(`detail-${id}`);
                if (el) el.classList.toggle('hidden');
            }





            async function fetchStats() {
                try {
                    const response = await fetch('/stats');
                    const data = await response.json();
                    
                    if (data.stats) {
                        document.getElementById('total-req').innerText = data.stats.total_requests.toLocaleString();
                        document.getElementById('allowed-req').innerText = data.stats.allowed_requests.toLocaleString();
                        document.getElementById('blocked-req').innerText = data.stats.blocked_requests.toLocaleString();
                    }
                    
                    if (data.logs && data.logs.length > 0) {
                        const tbody = document.getElementById('log-table');
                        
                        // Fix for Race Condition: Merge historical data even if WS already added rows
                        data.logs.forEach(log => {
                            const rowId = log.id || Math.random().toString(36).substr(2, 9);
                            
                            // Deduplication: Skip if row already exists (e.g. from Real-time WS)
                            // Deduplication: Skip if row already exists (e.g. from Real-time WS)
                            if (document.getElementById(`detail-${rowId}`)) return;
                                
                                // Count for Threat Intel (History)
                                countThreat(log);
                                const isBlocked = log.class === 'blocked';
                                const methodColor = getMethodColor(log.method);
                                
                                const tr = document.createElement('tr');
                                tr.className = `group cursor-pointer hover:bg-white/5 transition-all duration-300 font-mono ${isBlocked ? 'bg-red-500/5 hover:bg-red-500/10' : 'hover:bg-cyan-500/5'}`;
                                tr.onclick = () => toggleDetails(rowId);
                                
                                const statusPill = isBlocked 
                                    ? `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-red-400/10 text-red-400 border border-red-400/20">DENIED</span>`
                                    : `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-400/10 text-emerald-400 border border-emerald-400/20">ALLOWED</span>`;

                                tr.innerHTML = `
                                    <td class="p-4 text-white/60 text-xs">${log.time}</td>
                                    <td class="p-4"><span class="${methodColor} font-bold text-xs">${log.method}</span></td>
                                    <td class="p-4 text-xs group-hover:text-white transition-colors">
                                        <div class="flex flex-col gap-1">
                                            <div class="flex items-center gap-2 text-[10px] text-white/40 font-mono">
                                                <span>${log.client_ip}</span>
                                                <span class="text-holo-cyan">➜</span>
                                                <span>SERVER</span>
                                            </div>
                                            <div class="font-mono text-white/90 truncate w-96" title="${log.full_url || log.path}">${log.full_url || log.path}</div>
                                        </div>
                                    </td>
                                    <td class="p-4 text-right text-xs font-bold text-white/80">${log.score}</td>
                                    <td class="p-4 text-right">
                                        ${statusPill}
                                    </td>
                                `;
                                tbody.appendChild(tr);

                                // Details Row
                                const detailTr = document.createElement('tr');
                                detailTr.id = `detail-${rowId}`;
                                detailTr.className = "hidden bg-black/20";
                                const detailsJson = JSON.stringify(log.risk_details, null, 2);
                                detailTr.innerHTML = `
                                     <td colspan="5" class="p-0">
                                        <div class="m-2 rounded-lg bg-black/40 border border-white/5 p-4 text-xs">
                                            <div class="grid grid-cols-3 gap-6 mb-4 pb-4 border-b border-white/5">
                                                 <div><span class="block text-white/30 uppercase text-[10px] tracking-widest mb-1">Source IP</span><span class="font-mono text-white">${log.client_ip}</span></div>
                                                 <div><span class="block text-white/30 uppercase text-[10px] tracking-widest mb-1">Latency</span><span class="font-mono text-white">${log.latency_ms}ms</span></div>
                                                 <div class=""><span class="block text-white/30 uppercase text-[10px] tracking-widest mb-1">User Agent</span><span class="font-mono text-white/70 break-all whitespace-normal block" title="${log.user_agent}">${log.user_agent || 'UNKNOWN'}</span></div>
                                            </div>
                                            <div class="mb-4"><div class="text-holo-cyan text-[10px] uppercase tracking-widest mb-2 font-bold">Full URL</div><div class="bg-black/50 border border-white/10 p-3 rounded font-mono text-white/70 break-all select-all text-xs">${log.full_url || log.path}</div></div>
                                            ${log.payload_snippet ? `<div class="mb-4"><div class="text-holo-cyan text-[10px] uppercase tracking-widest mb-2 font-bold">Payload Dump</div><div class="bg-black/50 border border-white/10 p-3 rounded font-mono text-white/70 break-all select-all">${log.payload_snippet}</div></div>` : ''}
                                            <div><div class="text-holo-purple text-[10px] uppercase tracking-widest mb-2 font-bold">Risk Analysis</div><pre class="font-mono text-white/60 whitespace-pre-wrap text-[10px]">${detailsJson}</pre></div>
                                        </div>
                                    </td>
                                `;
                                tbody.appendChild(detailTr);
                        });
                    }

                    // Update Visuals after history load
                    updateThreatVisuals();
                } catch(e) { console.error("Stats Fetch Error", e); }
            }

            // Initialization
            fetchStats();
            connectWebSocket();
        </script>
    <!-- Tutorial Elements -->
    <div id="tutorial-overlay" class="fixed inset-0 z-50 hidden opacity-0 pointer-events-none"></div>
    <div id="tutorial-info" class="tutorial-box glass-panel p-6 rounded-xl border border-holo-cyan/30 hidden">
        <div class="flex flex-col gap-3">
            <h3 class="text-holo-cyan font-bold tracking-widest uppercase text-sm" id="tut-title">TITLE</h3>
            <p class="text-white/80 text-xs leading-relaxed" id="tut-text">Description goes here.</p>
            <div class="flex justify-end gap-2 mt-2">
                <button onclick="endTutorial()" class="px-3 py-1.5 rounded text-white/40 text-[10px] hover:text-white uppercase tracking-wider transition-colors">Skip</button>
                <button id="tut-next-btn" onclick="nextStep()" class="px-4 py-1.5 rounded bg-holo-cyan/10 border border-holo-cyan/50 text-holo-cyan text-[10px] hover:bg-holo-cyan/20 uppercase tracking-wider font-bold transition-all shadow-lg shadow-holo-cyan/10">Next</button>
            </div>
        </div>
    </div>

    <script>
        // Tutorial Logic
        let currentStep = -1;
        const tutorialSteps = [
            { 
                target: null, 
                title: "ETHERX SENTINEL", 
                text: "Welcome to the Advanced Security Protocol interface. This dashboard allows you to monitor and analyze network traffic in real-time. Let's take a quick tour of your command center." 
            },
            { 
                target: 'header-section', 
                title: "SYSTEM STATUS", 
                text: "The Top Bar displays key system information. 'System Active' confirms that the WAF is online and interception protocols are engaged. Version 11.0.4 is currently running." 
            },
            { 
                target: 'threat-panel', 
                title: "THREAT INTELLIGENCE", 
                text: "This panel visualizes active threats. It breaks down blocked requests by category: SQL Injections, XSS Scripting attacks, and Neural Anomalies detected by the AI model." 
            },
            { 
                target: 'stats-grid', 
                title: "TRAFFIC STATISTICS", 
                text: "Global metrics at a glance. Track the Total Request volume, Monitor Network Latency, and compare the ratio of Allowed vs. Blocked traffic." 
            },
            { 
                target: 'feed-panel', 
                title: "LIVE INSPECTION FEED", 
                text: "The main console streams logs in real-time. Each row represents a request. Click on a row to expand deep packet details, including Source IP, User Agent, and the full Risk Analysis JSON." 
            }
        ];

        function startTutorial() {
            currentStep = -1;
            const overlay = document.getElementById('tutorial-overlay');
            const info = document.getElementById('tutorial-info');
            
            overlay.classList.remove('hidden');
            requestAnimationFrame(() => overlay.classList.remove('opacity-0'));
            info.classList.remove('hidden');
            
            nextStep();
        }

        function endTutorial() {
            const overlay = document.getElementById('tutorial-overlay');
            const info = document.getElementById('tutorial-info');
            
            // Cleanup highlights
            document.querySelectorAll('.tutorial-highlight').forEach(el => {
                el.classList.remove('tutorial-highlight');
                el.style.zIndex = '';
            });

            overlay.classList.add('opacity-0');
            info.classList.remove('visible');
            
            setTimeout(() => {
                overlay.classList.add('hidden');
                info.classList.add('hidden');
            }, 500);
        }

        function nextStep() {
            // Cleanup previous
            if (currentStep >= 0) {
                const prev = tutorialSteps[currentStep];
                if (prev.target) {
                   const el = document.getElementById(prev.target);
                   if(el) {
                       el.classList.remove('tutorial-highlight');
                       el.style.zIndex = ''; 
                   }
                }
            }

            currentStep++;
            if (currentStep >= tutorialSteps.length) {
                endTutorial();
                return;
            }

            const step = tutorialSteps[currentStep];
            const info = document.getElementById('tutorial-info');
            const nextBtn = document.getElementById('tut-next-btn');
            
            // Update Text
            document.getElementById('tut-title').innerText = step.title;
            document.getElementById('tut-text').innerText = step.text;
            
            if (currentStep >= tutorialSteps.length - 1) {
                nextBtn.innerText = "Finish";
                nextBtn.onclick = endTutorial; 
            } else {
                nextBtn.innerText = "Next";
                nextBtn.onclick = nextStep;
            }

            // Positioning
            if (step.target) {
                const el = document.getElementById(step.target);
                if (el) {
                    el.classList.add('tutorial-highlight');
                    // Bring to front
                    // We need to verify if z-index conflict exists, but overlay uses huge shadow 
                    
                    const rect = el.getBoundingClientRect();
                    const infoRect = info.getBoundingClientRect();
                    
                    // Default: Bottom Right of element
                    let top = rect.bottom + 20;
                    let left = rect.left + (rect.width / 2) - (infoRect.width / 2);
                    
                    // Boundary Checks
                    if (left + infoRect.width > window.innerWidth) left = window.innerWidth - infoRect.width - 20;
                    if (left < 20) left = 20;
                    
                    // Vertical Clamp
                    if (top + infoRect.height > window.innerHeight) {
                        // If it doesn't fit below, try above
                        top = rect.top - infoRect.height - 20;
                        // If it doesn't fit above (e.g. Feed Panel), put it inside at the top
                        if (top < 80) top = rect.top + 20;
                    }

                    info.style.top = `${top}px`;
                    info.style.left = `${left}px`;
                }
            } else {
                // Center Screen
                info.style.top = '50%';
                info.style.left = '50%';
                info.style.transform = 'translate(-50%, -50%)';
            }

            // Animate In
            info.classList.remove('visible');
            requestAnimationFrame(() => {
                if(!step.target) info.style.transform = 'translate(-50%, -50%)'; // Keep center transform
                else info.style.transform = 'translateY(0)';
                
                info.classList.add('visible');
            });
        }
    </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
