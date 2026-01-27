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
DB_PATH = "wafel.db"

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
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM logs")
        total = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM logs WHERE class='blocked'")
        blocked = c.fetchone()[0]
        conn.close()
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

def log_to_db(entry):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Serialize risk_details to JSON if it's a dict
        risk_details_str = json.dumps(entry.get('risk_details', {}))
        
        c.execute('''INSERT INTO logs 
                     (timestamp, method, path, score, status, class, client_ip, risk_details, latency_ms, user_agent, payload_snippet) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (entry['time'], 
                   entry['method'], 
                   entry['path'], 
                   float(entry['score']), 
                   entry['status'], 
                   entry['class'], 
                   entry['client_ip'],
                   risk_details_str,
                   entry.get('latency_ms', 0.0),
                   entry.get('user_agent', ''),
                   entry.get('payload_snippet', '')
                  ))
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
            "full_url": f"{payload['path']}?{payload['query']}" if payload['query'] else payload['path'],
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
        </style>
    </head>
    <body class="h-screen flex flex-col overflow-hidden selection:bg-holo-cyan selection:text-black">
        
        <!-- Background Grid -->
        <div class="fixed inset-0 bg-cyber-grid bg-grid opacity-20 pointer-events-none z-0"></div>

        <!-- Navbar -->
        <nav class="border-b border-white/5 bg-black/20 backdrop-blur-md z-40">
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
                     <span class="font-mono text-xs text-white/30">V.11.0.4</span>
                </div>
            </div>
        </nav>

        <!-- Main Content -->
        <main class="relative flex-1 max-w-7xl mx-auto w-full p-6 grid grid-cols-1 lg:grid-cols-12 gap-8 min-h-0 z-10">
            
            <!-- Left Panel -->
            <div class="lg:col-span-4 flex flex-col gap-6">
                
                <!-- NEURAL GRID CARD -->
                <div class="glass-panel rounded-2xl p-6 relative flex flex-col items-center justify-center overflow-hidden min-h-[300px]">
                    <div class="absolute top-4 left-4 flex gap-2">
                        <div class="w-1 h-1 bg-holo-cyan rounded-full"></div>
                        <div class="w-1 h-1 bg-white/20 rounded-full"></div>
                    </div>
                    <div class="absolute top-4 right-4 text-[10px] font-mono text-white/30 tracking-widest">NEURAL_ENGINE_V6</div>

                    <!-- Neural Grid Container -->
                    <div class="relative w-64 h-64 flex items-center justify-center">
                        <div class="neural-grid-container" id="neural-grid">
                            <!-- Neurons Injected via JS -->
                        </div>
                         
                        <!-- Central Status Over Grid -->
                         <div class="absolute inset-0 flex items-center justify-center pointer-events-none">
                             <div class="backdrop-blur-sm bg-black/40 p-4 border border-white/10 rounded-lg text-center shadow-2xl">
                                 <div class="text-3xl font-black text-white tracking-[0.1em]" id="ai-status">ACTIVE</div>
                                 <div class="text-[9px] uppercase tracking-widest text-holo-cyan mt-1" id="ai-subtext">Deep Learning Inference</div>
                             </div>
                         </div>
                    </div>
                </div>

                <!-- Stats Grid -->
                <div class="grid grid-cols-2 gap-4">
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
            <div class="lg:col-span-8 flex flex-col">
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
                                    <th class="p-4 font-medium">Path</th>
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

            function connectWebSocket() {
                socket = new WebSocket(wsUrl);

                socket.onopen = function() {
                    console.log("Connected to Real-time Feed");
                    const modelEl = document.getElementById('model-name');
                    if (!modelEl.innerText.includes("LIVE")) modelEl.innerText += " • LIVE";
                };

                socket.onmessage = function(event) {
                    const msg = JSON.parse(event.data);
                    if (msg.type === 'new_log') {
                        updateDashboard(msg.data, msg.stats);
                    }
                };

                socket.onclose = function() {
                    console.log("Disconnected. Reconnecting...");
                    setTimeout(connectWebSocket, 3000);
                };
            }

            function updateDashboard(log, stats) {
                // 1. Update Stats
                document.getElementById('total-req').innerText = stats.total_requests.toLocaleString();
                document.getElementById('allowed-req').innerText = stats.allowed_requests.toLocaleString();
                document.getElementById('blocked-req').innerText = stats.blocked_requests.toLocaleString();
                
                // 2. Update Visuals
                const isBlocked = log.class === 'blocked';
                const statusEl = document.getElementById('ai-status');
                const subtextEl = document.getElementById('ai-subtext');
                const blockedCard = document.getElementById('blocked-card');
                
                if (isBlocked) {
                    statusEl.innerText = "THREAT DETECTED";
                    statusEl.classList.remove('text-white');
                    statusEl.classList.add('text-holo-red', 'animate-pulse');
                    
                    subtextEl.innerText = "NEURAL REJECTION ENGAGED";
                    subtextEl.classList.remove('text-holo-cyan');
                    subtextEl.classList.add('text-holo-red', 'font-bold');
                    
                    // Trigger Red Neurons
                    document.querySelectorAll('.neuron').forEach(n => {
                        n.classList.add('active-red');
                        setTimeout(() => n.classList.remove('active-red'), 2000);
                    });
                    
                    blockedCard.classList.add('ring-1', 'ring-holo-red');
                    
                    // Flash effect
                    document.body.style.boxShadow = "inset 0 0 100px rgba(255, 0, 85, 0.2)";
                    setTimeout(() => document.body.style.boxShadow = "none", 300);

                    // Reset visuals after 2.5 seconds
                    setTimeout(() => {
                        if(statusEl) {
                            statusEl.innerText = "ACTIVE";
                            statusEl.classList.add('text-white');
                            statusEl.classList.remove('text-holo-red', 'animate-pulse');
                        }
                        
                        if(subtextEl) {
                            subtextEl.innerText = "Deep Learning Inference";
                            subtextEl.classList.add('text-holo-cyan');
                            subtextEl.classList.remove('text-holo-red', 'font-bold');
                        }
                        
                        if(blockedCard) blockedCard.classList.remove('ring-1', 'ring-holo-red');
                    }, 2500);
                } else {
                     // Random neural activation on valid request
                    const neurons = document.querySelectorAll('.neuron');
                    if(neurons.length > 0) {
                        for(let i=0; i<3; i++) {
                            const n = neurons[Math.floor(Math.random() * neurons.length)];
                            if(n) {
                                n.classList.add('active');
                                setTimeout(() => n.classList.remove('active'), 500);
                            }
                        }
                    }
                }
            }

            // Neural Grid Initialization
            function initNeuralGrid() {
                const grid = document.getElementById('neural-grid');
                if(!grid) return;
                
                // Keep grid clear initially
                grid.innerHTML = '';

                // Create 64 neurons (8x8)
                for (let i = 0; i < 64; i++) {
                    const neuron = document.createElement('div');
                    neuron.className = 'neuron';
                    grid.appendChild(neuron);
                }
                
                // Backround idle animation
                setInterval(() => {
                    const neurons = document.querySelectorAll('.neuron');
                    if(neurons.length > 0) {
                        const randomNeuron = neurons[Math.floor(Math.random() * neurons.length)];
                        if(randomNeuron) {
                            randomNeuron.classList.add('active');
                            setTimeout(() => randomNeuron.classList.remove('active'), 800);
                        }
                    }
                }, 200);
            }

                // 3. Add to Table (Prepend)
                const tbody = document.getElementById('log-table');
                
                const methodColor = getMethodColor(log.method);
                const rowId = log.id || Math.floor(Math.random() * 1000000); 

                const tr = document.createElement('tr');
                tr.className = `group cursor-pointer hover:bg-white/5 transition-all duration-300 font-mono ${isBlocked ? 'bg-red-500/5 hover:bg-red-500/10' : 'hover:bg-cyan-500/5'}`;
                tr.onclick = () => toggleDetails(rowId);
                
                // Status Pill
                const statusPill = isBlocked 
                    ? `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-red-400/10 text-red-400 border border-red-400/20 shadow-[0_0_10px_rgba(248,113,113,0.1)]">DENIED</span>`
                    : `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-400/10 text-emerald-400 border border-emerald-400/20">ALLOWED</span>`;

                tr.innerHTML = `
                    <td class="p-4 text-white/60 text-xs">${log.time}</td>
                    <td class="p-4"><span class="${methodColor} font-bold text-xs">${log.method}</span></td>
                    <td class="p-4 text-white/90 text-xs max-w-xs truncate group-hover:text-holo-cyan transition-colors" title="${log.path}">${log.path}</td>
                    <td class="p-4 text-right text-xs font-bold text-white/80">${log.score}</td>
                    <td class="p-4 text-right">
                        ${statusPill}
                    </td>
                `;
                
                // Detail Row
                const detailTr = document.createElement('tr');
                detailTr.id = `detail-${rowId}`;
                detailTr.className = "hidden bg-black/20";
                const detailsJson = JSON.stringify(log.risk_details || {}, null, 2);
                
                detailTr.innerHTML = `
                    <td colspan="5" class="p-0">
                         <div class="m-2 rounded-lg bg-black/40 border border-white/5 p-4 text-xs">
                            <div class="grid grid-cols-3 gap-6 mb-4 pb-4 border-b border-white/5">
                                 <div>
                                     <span class="block text-white/30 uppercase text-[10px] tracking-widest mb-1">Source IP</span>
                                     <span class="font-mono text-white">${log.client_ip}</span>
                                 </div>
                                 <div>
                                     <span class="block text-white/30 uppercase text-[10px] tracking-widest mb-1">Latency</span>
                                     <span class="font-mono text-white">${log.latency_ms}ms</span>
                                 </div>
                                 <div class="truncate">
                                     <span class="block text-white/30 uppercase text-[10px] tracking-widest mb-1">User Agent</span>
                                     <span class="font-mono text-white/70 truncate block" title="${log.user_agent}">${log.user_agent || 'UNKNOWN'}</span>
                                 </div>
                            </div>
                             ${log.payload ? `<div class="mb-4"><div class="text-holo-cyan text-[10px] uppercase tracking-widest mb-2 font-bold">Payload Dump</div><div class="bg-black/50 border border-white/10 p-3 rounded font-mono text-white/70 break-all select-all">${log.payload}</div></div>` : ''}
                            <div>
                                <div class="text-holo-purple text-[10px] uppercase tracking-widest mb-2 font-bold">Risk Analysis</div>
                                <pre class="font-mono text-white/60 whitespace-pre-wrap text-[10px]">${detailsJson}</pre>
                            </div>
                        </div>
                    </td>
                `;

                // Insert at top with animation
                tr.style.opacity = '0';
                tr.style.transform = 'translateY(-10px)';
                
                tbody.insertBefore(detailTr, tbody.firstChild);
                tbody.insertBefore(tr, tbody.firstChild);
                
                requestAnimationFrame(() => {
                    tr.style.opacity = '1';
                    tr.style.transform = 'translateY(0)';
                });
                
                // Limit rows
                if (tbody.children.length > 50) {
                    tbody.removeChild(tbody.lastChild);
                    tbody.removeChild(tbody.lastChild);
                }
            }

            async function fetchStats() {
                try {
                    const response = await fetch('/stats');
                    const data = await response.json();
                    
                    document.getElementById('total-req').innerText = data.stats.total_requests.toLocaleString();
                    document.getElementById('allowed-req').innerText = data.stats.allowed_requests.toLocaleString();
                    document.getElementById('blocked-req').innerText = data.stats.blocked_requests.toLocaleString();
                    if (data.logs.length > 0) {
                         document.getElementById('latency').innerText = data.logs[0].latency_ms || 8;
                    }
                    
                    // Logs Render
                    const tbody = document.getElementById('log-table');
                    tbody.innerHTML = "";
                    
                    data.logs.forEach(log => {
                        const isBlocked = log.class === 'blocked';
                        const methodColor = getMethodColor(log.method);
                        const rowId = log.id;

                        const tr = document.createElement('tr');
                        tr.className = `group cursor-pointer hover:bg-white/5 transition-all duration-300 font-mono ${isBlocked ? 'bg-red-500/5 hover:bg-red-500/10' : 'hover:bg-cyan-500/5'}`;
                        tr.onclick = () => toggleDetails(rowId);
                        
                        const statusPill = isBlocked 
                            ? `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-red-400/10 text-red-400 border border-red-400/20">DENIED</span>`
                            : `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-400/10 text-emerald-400 border border-emerald-400/20">ALLOWED</span>`;

                        tr.innerHTML = `
                             <td class="p-4 text-white/60 text-xs">${log.time}</td>
                            <td class="p-4"><span class="${methodColor} font-bold text-xs">${log.method}</span></td>
                            <td class="p-4 text-white/90 text-xs max-w-xs truncate group-hover:text-holo-cyan transition-colors" title="${log.path}">${log.path}</td>
                            <td class="p-4 text-right text-xs font-bold text-white/80">${log.score}</td>
                            <td class="p-4 text-right">
                                ${statusPill}
                            </td>
                        `;
                        tbody.appendChild(tr);

                        const detailTr = document.createElement('tr');
                        detailTr.id = `detail-${rowId}`;
                        detailTr.className = "hidden bg-black/20";
                        
                        const detailsJson = JSON.stringify(log.risk_details, null, 2);
                        
                        detailTr.innerHTML = `
                             <td colspan="5" class="p-0">
                                <div class="m-2 rounded-lg bg-black/40 border border-white/5 p-4 text-xs">
                                    <div class="grid grid-cols-3 gap-6 mb-4 pb-4 border-b border-white/5">
                                         <div>
                                             <span class="block text-white/30 uppercase text-[10px] tracking-widest mb-1">Source IP</span>
                                             <span class="font-mono text-white">${log.client_ip}</span>
                                         </div>
                                         <div>
                                             <span class="block text-white/30 uppercase text-[10px] tracking-widest mb-1">Latency</span>
                                             <span class="font-mono text-white">${log.latency_ms}ms</span>
                                         </div>
                                         <div class="truncate">
                                             <span class="block text-white/30 uppercase text-[10px] tracking-widest mb-1">User Agent</span>
                                             <span class="font-mono text-white/70 truncate block" title="${log.user_agent}">${log.user_agent || 'UNKNOWN'}</span>
                                         </div>
                                    </div>
                                     ${log.payload_snippet ? `<div class="mb-4"><div class="text-holo-cyan text-[10px] uppercase tracking-widest mb-2 font-bold">Payload Dump</div><div class="bg-black/50 border border-white/10 p-3 rounded font-mono text-white/70 break-all select-all">${log.payload_snippet}</div></div>` : ''}
                                    <div>
                                        <div class="text-holo-purple text-[10px] uppercase tracking-widest mb-2 font-bold">Risk Analysis</div>
                                        <pre class="font-mono text-white/60 whitespace-pre-wrap text-[10px]">${detailsJson}</pre>
                                    </div>
                                </div>
                            </td>
                        `;
                        tbody.appendChild(detailTr);
                    });

                } catch (e) { console.error(e); }
            }
            
            function toggleDetails(id) {
                const el = document.getElementById(`detail-${id}`);
                if (el) {
                    el.classList.toggle('hidden');
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
            
            // Initialization
            fetchStats();
            connectWebSocket();
            initNeuralGrid();
        </script>
    </body>
    </html>
    """

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
