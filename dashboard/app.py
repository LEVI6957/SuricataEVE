"""
app.py — Suricata Auto Block Dashboard
FastAPI backend: REST API + WebSocket real-time + Webhook outbound

Author: Levi (github.com/LEVI6957)
"""

import asyncio
import json
import logging
import os
import subprocess
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import aiofiles
import httpx
from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect,
    HTTPException, Request, Header, Depends
)
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ─── Config ───────────────────────────────────────────────────────────────────
EVE_LOG_PATH  = os.getenv("EVE_LOG_PATH",  "/var/log/suricata/eve.json")
BLOCKED_LOG   = os.getenv("BLOCKED_LOG",   "/app/blocked_ips.log")
SETTINGS_FILE = "/app/settings.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("dashboard")

# ─── In-memory State ──────────────────────────────────────────────────────────
recent_alerts: deque = deque(maxlen=200)     # buffer 200 alert terbaru
blocked_ips: list[dict] = []                  # [{ip, timestamp, signature, count}]
alert_counts: dict = defaultdict(int)
stats = {"total_alerts": 0, "total_blocked": 0, "start_time": time.time()}
ws_clients: list[WebSocket] = []
webhook_log: deque = deque(maxlen=50)         # log 50 pengiriman webhook terakhir


# ─── Settings Helper ─────────────────────────────────────────────────────────
def load_settings() -> dict:
    try:
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {
            "webhook_url": "",
            "webhook_headers": {},
            "threshold": 3,
            "severity": 2,
            "interval": 10,
            "secret_token": "",
        }


def save_settings(data: dict):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(data, f, indent=2)


# ─── WebSocket Broadcaster ───────────────────────────────────────────────────
async def broadcast(event: dict):
    """Kirim event ke semua WebSocket client yang terhubung."""
    dead = []
    msg = json.dumps(event)
    for ws in ws_clients:
        try:
            await ws.send_text(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        ws_clients.remove(ws)


# ─── Webhook Engine ───────────────────────────────────────────────────────────
async def send_webhook(payload: dict):
    """Kirim notifikasi ke webhook URL yang dikonfigurasi (retry 3x)."""
    settings = load_settings()
    url = settings.get("webhook_url", "").strip()
    if not url:
        return

    headers = {"Content-Type": "application/json"}
    headers.update(settings.get("webhook_headers", {}))

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    result_entry = {"timestamp": ts, "url": url, "status": None, "error": None}

    for attempt in range(1, 4):
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(url, json=payload, headers=headers)
                result_entry["status"] = r.status_code
                if r.status_code < 400:
                    log.info(f"Webhook OK [{r.status_code}]: {url}")
                    break
                else:
                    log.warning(f"Webhook gagal [{r.status_code}] attempt {attempt}")
        except Exception as e:
            result_entry["error"] = str(e)
            log.error(f"Webhook error attempt {attempt}: {e}")
            await asyncio.sleep(2 ** attempt)

    webhook_log.appendleft(result_entry)


# ─── Eve.json Tail Task ───────────────────────────────────────────────────────
async def tail_eve():
    """Background task: tail eve.json dan broadcast event ke WebSocket."""
    while not os.path.exists(EVE_LOG_PATH):
        log.info(f"Menunggu {EVE_LOG_PATH} ...")
        await asyncio.sleep(5)

    log.info(f"Mulai membaca {EVE_LOG_PATH}")
    settings = load_settings()

    async with aiofiles.open(EVE_LOG_PATH, "r") as f:
        await f.seek(0, 2)  # Skip ke akhir file
        while True:
            line = await f.readline()
            if not line:
                await asyncio.sleep(0.3)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            settings = load_settings()
            severity   = event.get("alert", {}).get("severity", 99)
            src_ip     = event.get("src_ip", "")
            signature  = event.get("alert", {}).get("signature", "N/A")
            category   = event.get("alert", {}).get("category", "N/A")
            ts         = event.get("timestamp", datetime.now(timezone.utc).isoformat())

            if severity > settings.get("severity", 2):
                continue

            stats["total_alerts"] += 1
            alert_counts[src_ip] += 1
            count = alert_counts[src_ip]

            alert_payload = {
                "type":      "alert",
                "src_ip":    src_ip,
                "signature": signature,
                "category":  category,
                "severity":  severity,
                "count":     count,
                "threshold": settings.get("threshold", 3),
                "timestamp": ts,
            }
            recent_alerts.appendleft(alert_payload)

            # Broadcast ke UI
            await broadcast(alert_payload)

            # Auto-block jika mencapai threshold
            threshold = settings.get("threshold", 3)
            if count >= threshold and not any(b["ip"] == src_ip for b in blocked_ips):
                blocked_entry = {
                    "ip":        src_ip,
                    "timestamp": ts,
                    "signature": signature,
                    "count":     count,
                }
                blocked_ips.insert(0, blocked_entry)
                stats["total_blocked"] += 1

                block_payload = {**alert_payload, "type": "blocked"}
                await broadcast(block_payload)

                # Kirim webhook
                await send_webhook({
                    "event":     "BLOCKED",
                    "ip":        src_ip,
                    "signature": signature,
                    "category":  category,
                    "severity":  severity,
                    "hit_count": count,
                    "timestamp": ts,
                })

                # Tulis log
                with open(BLOCKED_LOG, "a") as blf:
                    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    blf.write(f"{now} | BLOCKED | {src_ip} | {signature}\n")

            elif count == 1:
                # Kirim webhook untuk alert pertama (high severity)
                if severity == 1:
                    await send_webhook({
                        "event":     "HIGH_ALERT",
                        "ip":        src_ip,
                        "signature": signature,
                        "category":  category,
                        "severity":  severity,
                        "timestamp": ts,
                    })


# ─── Lifespan ─────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(tail_eve())
    yield
    task.cancel()


# ─── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(title="Suricata Dashboard", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")


# ─── Auth ─────────────────────────────────────────────────────────────────────
def verify_token(x_token: Optional[str] = Header(default=None)):
    settings = load_settings()
    secret = settings.get("secret_token", "").strip()
    if not secret:
        return  # Token tidak dikonfigurasi, skip auth
    if x_token != secret:
        raise HTTPException(status_code=403, detail="Invalid token")


# ─── Routes ───────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index():
    async with aiofiles.open("static/index.html", "r") as f:
        return await f.read()


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    ws_clients.append(ws)
    # Kirim 50 alert terakhir saat pertama connect
    for alert in list(recent_alerts)[:50]:
        await ws.send_text(json.dumps(alert))
    try:
        while True:
            await ws.receive_text()  # Keep alive
    except WebSocketDisconnect:
        if ws in ws_clients:
            ws_clients.remove(ws)


@app.get("/api/stats")
async def get_stats():
    uptime_sec = int(time.time() - stats["start_time"])
    return {
        "total_alerts":  stats["total_alerts"],
        "total_blocked": stats["total_blocked"],
        "active_clients": len(ws_clients),
        "uptime_seconds": uptime_sec,
        "top_attackers":  sorted(
            [{"ip": k, "count": v} for k, v in alert_counts.items()],
            key=lambda x: x["count"], reverse=True
        )[:10],
    }


@app.get("/api/blocked")
async def get_blocked():
    return blocked_ips


@app.post("/api/unblock/{ip}")
async def unblock_ip(ip: str, _=Depends(verify_token)):
    global blocked_ips
    try:
        result = subprocess.run(
            ["ufw", "delete", "deny", "from", ip, "to", "any"],
            capture_output=True, text=True
        )
        blocked_ips = [b for b in blocked_ips if b["ip"] != ip]
        await broadcast({"type": "unblocked", "ip": ip})
        return {"status": "ok", "ip": ip, "ufw_output": result.stdout.strip()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/alerts")
async def get_alerts(limit: int = 100):
    return list(recent_alerts)[:limit]


@app.get("/api/settings")
async def get_settings(_=Depends(verify_token)):
    s = load_settings()
    # Jangan expose secret_token ke UI secara penuh
    if s.get("secret_token"):
        s["secret_token"] = "••••••••"
    return s


class SettingsUpdate(BaseModel):
    webhook_url:     Optional[str]  = None
    webhook_headers: Optional[dict] = None
    threshold:       Optional[int]  = None
    severity:        Optional[int]  = None
    interval:        Optional[int]  = None
    secret_token:    Optional[str]  = None


@app.post("/api/settings")
async def update_settings(body: SettingsUpdate, _=Depends(verify_token)):
    s = load_settings()
    if body.webhook_url     is not None: s["webhook_url"]     = body.webhook_url
    if body.webhook_headers is not None: s["webhook_headers"] = body.webhook_headers
    if body.threshold       is not None: s["threshold"]       = body.threshold
    if body.severity        is not None: s["severity"]        = body.severity
    if body.interval        is not None: s["interval"]        = body.interval
    if body.secret_token and body.secret_token != "••••••••":
        s["secret_token"] = body.secret_token
    save_settings(s)
    return {"status": "saved"}


@app.post("/api/webhook/test")
async def test_webhook(_=Depends(verify_token)):
    payload = {
        "event":     "TEST",
        "message":   "Webhook test dari Suricata Dashboard",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await send_webhook(payload)
    return {"status": "sent", "log": list(webhook_log)[:1]}


@app.get("/api/webhook/log")
async def get_webhook_log(_=Depends(verify_token)):
    return list(webhook_log)


# ─── Internal endpoint (dipanggil oleh auto_block.py) ────────────────────────
@app.post("/internal/event")
async def internal_event(request: Request):
    """Endpoint internal untuk menerima event dari auto_block.py."""
    try:
        data = await request.json()
        event_type = data.get("type", "alert")
        if event_type == "blocked":
            blocked_ips.insert(0, {
                "ip":        data.get("ip"),
                "timestamp": data.get("timestamp"),
                "signature": data.get("signature"),
                "count":     data.get("count", 0),
            })
            stats["total_blocked"] += 1
        stats["total_alerts"] += 1
        await broadcast(data)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}
