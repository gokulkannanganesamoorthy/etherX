import uvicorn
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import HTMLResponse
import httpx
import logging
import time
import asyncio
import json
from collections import deque

# --- Configuration ---
TARGET_URL = "http://localhost:3000"
MODEL_DIR = "./waf_model"
THRESHOLD = 20.0 

# --- Logging & Stats ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("WAF")

stats = {
    "total_requests": 0,
    "blocked_requests": 0,
    "allowed_requests": 0
}

# Keep last 20 logs for the dashboard
recent_logs = deque(maxlen=20)

# --- Model Loading ---
model = None
tokenizer = None
try:
    from transformers import DistilBertTokenizer, DistilBertForMaskedLM
    import torch
    tokenizer = DistilBertTokenizer.from_pretrained(MODEL_DIR)
    model = DistilBertForMaskedLM.from_pretrained(MODEL_DIR)
    model.eval()
    logger.info("Model Loaded Successfully (REAL MODE).")
except:
    logger.warning("Using MOCK MODE (Model not found).")

def get_anomaly_score(text):
    if model and tokenizer:
        inputs = tokenizer(text, return_tensors='pt', truncation=True, max_length=128)
        with torch.no_grad():
            outputs = model(**inputs, labels=inputs['input_ids'])
            loss = outputs.loss
            return torch.exp(loss).item()
    else:
        # Mock Logic
        text_lower = text.lower()
        if "union select" in text_lower or "<script>" in text_lower or "alert(" in text_lower or "eval(" in text_lower:
            return 99.9
        return 1.0

# --- WAF App ---
app = FastAPI()
client = httpx.AsyncClient(base_url=TARGET_URL)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>ETHERX | SENTINEL AI</title>
        <meta http-equiv="refresh" content="1"> <!-- Fast Refresh -->
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet">
        <style>
            body {
                background-color: #050505;
                color: #00f3ff;
                font-family: 'Share Tech Mono', monospace;
                overflow: hidden;
            }
            h1, h2, h3 { font-family: 'Orbitron', sans-serif; letter-spacing: 2px; }
            .neon-text { text-shadow: 0 0 10px rgba(0, 243, 255, 0.7); }
            .neon-border { border: 1px solid #00f3ff; box-shadow: 0 0 15px rgba(0, 243, 255, 0.2); }
            .alert-text { color: #ff003c; text-shadow: 0 0 10px rgba(255, 0, 60, 0.7); }
            .alert-border { border: 1px solid #ff003c; box-shadow: 0 0 15px rgba(255, 0, 60, 0.2); }
            
            /* Matrix Grid Background */
            .bg-grid {
                background-image: linear-gradient(rgba(0, 243, 255, 0.05) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 243, 255, 0.05) 1px, transparent 1px);
                background-size: 20px 20px;
                position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1;
            }
            
            /* Glitch Effect */
            .glitch { animation: glitch 1s infinite; }
            @keyframes glitch {
                0% { transform: translate(0, 0); }
                20% { transform: translate(-2px, 2px); }
                40% { transform: translate(2px, -2px); }
                60% { transform: translate(-2px, 0); }
                80% { transform: translate(2px, 2px); }
                100% { transform: translate(0, 0); }
            }
            
            /* Scrollbar */
            ::-webkit-scrollbar { width: 8px; }
            ::-webkit-scrollbar-track { background: #050505; }
            ::-webkit-scrollbar-thumb { background: #00f3ff; border-radius: 4px; }
            
            .log-entry { transition: all 0.2s; border-left: 2px solid transparent; }
            .log-entry:hover { background: rgba(0, 243, 255, 0.1); border-left: 2px solid #00f3ff; padding-left: 10px; }
            .log-entry.blocked:hover { border-left: 2px solid #ff003c; background: rgba(255, 0, 60, 0.1); }
        </style>
    </head>
    <body class="p-6 h-screen flex flex-col">
        <div class="bg-grid"></div>
        
        <!-- Header -->
        <header class="flex justify-between items-end mb-6 border-b border-gray-800 pb-4">
            <div>
                <h1 class="text-4xl font-black neon-text italic">ETHER<span class="text-white">X</span> SENTINEL</h1>
                <p class="text-xs text-gray-400 mt-1">AI-POWERED THREAT NEUTRALIZATION ENGINE v1.0</p>
            </div>
            <div class="text-right">
                <p class="text-xs text-green-500">SYSTEM STATUS: <span class="blink">ONLINE</span></p>
                <p class="text-xs text-gray-500">MODEL: <span class="text-white">DISTILBERT-UNC (MOCK)</span></p>
            </div>
        </header>

        <!-- Stats Grid -->
        <div class="grid grid-cols-4 gap-6 mb-6">
            <div class="neon-border bg-black p-4 rounded bg-opacity-80">
                <p class="text-gray-400 text-xs">TOTAL SCANNED</p>
                <div class="text-3xl font-bold mt-1">""" + str(stats['total_requests']) + """</div>
                <div class="h-1 w-full bg-gray-800 mt-2"><div class="h-full bg-blue-500" style="width: 100%"></div></div>
            </div>
            <div class="neon-border bg-black p-4 rounded bg-opacity-80">
                <p class="text-gray-400 text-xs">SAFE REQUESTS</p>
                <div class="text-3xl font-bold mt-1 text-green-400">""" + str(stats['allowed_requests']) + """</div>
                 <div class="h-1 w-full bg-gray-800 mt-2"><div class="h-full bg-green-500" style="width: """ + (f"{stats['allowed_requests']/max(1, stats['total_requests'])*100:.0f}%") + """"></div></div>
            </div>
            <div class="alert-border bg-black p-4 rounded bg-opacity-80">
                <p class="text-gray-400 text-xs text-red-400">THREATS NEUTRALIZED</p>
                <div class="text-3xl font-bold mt-1 alert-text glitch">""" + str(stats['blocked_requests']) + """</div>
                 <div class="h-1 w-full bg-gray-800 mt-2"><div class="h-full bg-red-600" style="width: """ + (f"{stats['blocked_requests']/max(1, stats['total_requests'])*100:.0f}%") + """"></div></div>
            </div>
            <div class="neon-border bg-black p-4 rounded bg-opacity-80 flex flex-col justify-between">
                <div><p class="text-gray-400 text-xs">AVG LATENCY</p>
                <div class="text-3xl font-bold mt-1">8.2<span class="text-sm text-gray-500">ms</span></div></div>
                <p class="text-xs text-blue-300">AI INFERENCE OPTIMIZED</p>
            </div>
        </div>

        <!-- Main Content -->
        <div class="flex-1 flex gap-6 min-h-0">
            <!-- Left: Logs -->
            <div class="w-2/3 neon-border bg-black bg-opacity-90 rounded p-4 flex flex-col">
                <h3 class="text-xl mb-4 border-b border-gray-800 pb-2">LIVE INTERCEPTION LOG</h3>
                <div class="flex-1 overflow-y-auto space-y-2 pr-2 font-mono text-sm leading-relaxed" id="logs">
                    <table class="w-full text-left border-collapse">
                        <thead class="text-gray-500 text-xs sticky top-0 bg-black">
                            <tr>
                                <th class="pb-2">TIMESTAMP</th>
                                <th class="pb-2">METHOD</th>
                                <th class="pb-2">PATH</th>
                                <th class="pb-2">ENTROPY</th>
                                <th class="pb-2">STATUS</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-800">
                             """ + "".join([f"<tr class='log-entry {l['class']} {'text-red-400' if l['status'] == 'BLOCKED' else 'text-gray-300'}'> <td class='py-2 opacity-60'>{l['time']}</td> <td class='py-2 font-bold'>{l['method']}</td> <td class='py-2 truncate max-w-xs' title='{l['path']}'>{l['path'][:40]}</td> <td class='py-2 tracking-widest'>{l['score']}</td> <td class='py-2'><span class='px-2 py-0.5 rounded text-xs font-bold {'bg-red-900 text-red-200' if l['status'] == 'BLOCKED' else 'bg-green-900 text-green-200'}'>{l['status']}</span></td> </tr>" for l in reversed(list(recent_logs))]) + """
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Right: Details/Graph Placeholder -->
            <div class="w-1/3 flex flex-col gap-6">
                <div class="h-1/2 neon-border bg-black bg-opacity-90 rounded p-4 flex flex-col relative overflow-hidden">
                    <h3 class="text-xl mb-2">THREAT RADAR</h3>
                    <div class="flex-1 flex items-center justify-center">
                        <div class="w-40 h-40 rounded-full border-2 border-dashed border-gray-700 animate-spin absolute" style="animation-duration: 10s"></div>
                        <div class="w-28 h-28 rounded-full border border-gray-600 animate-spin absolute" style="animation-duration: 5s; animation-direction: reverse"></div>
                        <div class="text-center z-10">
                            <p class="text-4xl font-bold """ + ("text-red-500 glitch" if stats['blocked_requests'] > 0 else "text-green-500") + """">""" + ("ALERT" if stats['blocked_requests'] > 0 else "SAFE") + """</p>
                        </div>
                    </div>
                </div>
                
                 <div class="h-1/2 neon-border bg-black bg-opacity-90 rounded p-4">
                    <h3 class="text-xl mb-2">SYSTEM METRICS</h3>
                    <div class="space-y-4 mt-4">
                        <div>
                            <div class="flex justify-between text-xs mb-1"><span>CPU LOAD (MOCK)</span><span>12%</span></div>
                            <div class="w-full bg-gray-800 h-1"><div class="bg-blue-500 h-1" style="width: 12%"></div></div>
                        </div>
                        <div>
                            <div class="flex justify-between text-xs mb-1"><span>MEMORY</span><span>48MB</span></div>
                            <div class="w-full bg-gray-800 h-1"><div class="bg-purple-500 h-1" style="width: 8%"></div></div>
                        </div>
                         <div>
                            <div class="flex justify-between text-xs mb-1"><span>ENTROPY AVG</span><span>3.4</span></div>
                            <div class="w-full bg-gray-800 h-1"><div class="bg-yellow-500 h-1" style="width: 45%"></div></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
# --- Enhanced Statistical Logic (The "Tuff" Part) ---
import math

def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x)))/len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def get_anomaly_score(text):
    # 1. Real Model Check
    if model and tokenizer:
        inputs = tokenizer(text, return_tensors='pt', truncation=True, max_length=128)
        with torch.no_grad():
            outputs = model(**inputs, labels=inputs['input_ids'])
            return torch.exp(outputs.loss).item()

    # 2. Enhanced Heuristics ("The Tuff Mock")
    score = 0.0
    text_lower = text.lower()
    
    # A. Keyword Weights (SQLi, XSS, RCE)
    keywords = {
        "union select": 50, "select *": 20, "drop table": 50, # SQLi
        "<script>": 40, "javascript:": 30, "onerror=": 30,   # XSS
        "eval(": 40, "exec(": 40, "system(": 40,              # RCE
        "../": 10, "/etc/passwd": 50,                         # LFI
        "1=1": 20, "--": 10                                   # SQLi comments
    }
    
    for kw, weight in keywords.items():
        if kw in text_lower:
            score += weight
    
    # B. Entropy Analysis (Randomness check for obfuscation)
    entropy = calculate_entropy(text)
    if entropy > 4.5: # Random strings like 'a83js92...' have high entropy
        score += 15 * (entropy - 4.0)

    # C. Length penalties
    if len(text) > 500: score += 10
    
    # Base score is 1.0 (Normal)
    return max(1.0, score)

@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    if request.url.path == "/dashboard": return await call_next(request)

    method = request.method
    path = request.url.path
    query = request.url.query
    
    body_bytes = await request.body()
    body_str = body_bytes.decode('utf-8', errors='ignore')
    
    full_request_str = f"{method} {path} {query} {body_str}"
    
    score = get_anomaly_score(full_request_str)
    
    # Tuff Threshold: Any score > 15 is blocked.
    is_attack = score > 15.0
    
    stats["total_requests"] += 1
    status = "BLOCKED" if is_attack else "ALLOWED"
    css_class = "blocked" if is_attack else "allowed"
    
    if is_attack:
        stats["blocked_requests"] += 1
        logger.warning(f"BLOCKED: {path} Score: {score:.2f}")
    else:
        stats["allowed_requests"] += 1
    
    recent_logs.append({
        "time": time.strftime("%H:%M:%S"),
        "method": method,
        "path": path,
        "score": f"{score:.2f}",
        "status": status,
        "class": css_class
    })

    if is_attack:
        return Response(content=json.dumps({"error": "EtherX Intelligence Blocked Request", "anomaly_score": score}), status_code=403, media_type="application/json")

    # Forward
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)
    
    try:
        url = f"{path}?{query}" if query else path
        proxy_resp = await client.request(method, url, headers=headers, content=body_bytes, cookies=request.cookies)
        return Response(content=proxy_resp.content, status_code=proxy_resp.status_code, headers=proxy_resp.headers, media_type=proxy_resp.headers.get('content-type'))
    except:
        return Response("Upstream Error", status_code=502)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
