"""
app.py — Suricata Auto Block Dashboard
FastAPI backend: REST API + WebSocket real-time + Webhook outbound

Author: Levi (github.com/LEVI6957)
"""

import asyncio
import ipaddress
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
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ─── Config ───────────────────────────────────────────────────────────────────
EVE_LOG_PATH  = os.getenv("EVE_LOG_PATH",  "/var/log/suricata/eve.json")
BLOCKED_LOG   = os.getenv("BLOCKED_LOG",   "/app/blocked_ips.log")
ALERT_COUNTS  = os.getenv("ALERT_COUNTS",  "/app/alert_counts.json")
SETTINGS_FILE = os.getenv("SETTINGS_FILE", "/app/settings.json")
IPTABLES_CHAIN = "SURICATA_BLOCK"

# ─── Kredensial Login (dibaca dari environment variable) ─────────────────────
DASHBOARD_USER = os.getenv("DASHBOARD_USER", "admin")
DASHBOARD_PASS = os.getenv("DASHBOARD_PASS", "admin123")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("dashboard")

# ─── In-memory State ──────────────────────────────────────────────────────────
recent_alerts: deque = deque(maxlen=200)
blocked_ips: list[dict] = []
alert_counts: dict = defaultdict(int)
stats = {"total_alerts": 0, "total_blocked": 0, "start_time": time.time()}
ws_clients: list[WebSocket] = []
webhook_log: deque = deque(maxlen=50)


# ─── Settings Helper ──────────────────────────────────────────────────────────
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


# ─── WebSocket Broadcaster ────────────────────────────────────────────────────
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
def _format_discord_payload(payload: dict) -> dict:
    """Format payload khusus untuk Discord webhook."""
    event = payload.get("event", "EVENT")
    ip    = payload.get("ip", "N/A")
    sig   = payload.get("signature", "N/A")
    sev   = payload.get("severity", "N/A")
    ts    = payload.get("timestamp", "")

    # Pilih warna berdasarkan event type
    color = {
        "BLOCKED":          0xEF4444,   # merah
        "HIGH_ALERT":       0xF59E0B,   # kuning
        "TEST":             0x6366F1,   # ungu
        "WHITELIST_ADD":    0x22C55E,   # hijau
        "WHITELIST_REMOVE": 0xF97316,   # orange
        "UNBLOCKED":        0x3B82F6,   # biru
        "LOGIN":            0xFCD34D,   # emas terang
    }.get(event, 0x64748B)

    title_icon = {
        "BLOCKED":          "🔒 IP Diblok",
        "HIGH_ALERT":       "⚠️ High Alert",
        "TEST":             "🧪 Test Webhook",
        "WHITELIST_ADD":    "✅ Masuk Whitelist",
        "WHITELIST_REMOVE": "❌ Keluar Whitelist",
        "UNBLOCKED":        "🔓 IP Dibebaskan",
        "LOGIN":            "🎉😎🔥 BOS LOGIN CUI!! 🔥😎🎉",
    }.get(event, f"📡 {event}")

    embed = {
        "title": title_icon,
        "color": color,
        "timestamp": ts if ts else datetime.now(timezone.utc).isoformat(),
        "footer": {"text": "Suricata Auto Block Dashboard"},
        "fields": [],
    }

    if ip and ip != "N/A":
        embed["fields"].append({"name": "IP Penyerang", "value": f"`{ip}`", "inline": True})
    if sig and sig != "N/A":
        embed["fields"].append({"name": "Signature", "value": sig[:256], "inline": False})
    if sev and sev != "N/A":
        embed["fields"].append({"name": "Severity", "value": str(sev), "inline": True})
    if payload.get("hit_count"):
        embed["fields"].append({"name": "Hit Count", "value": str(payload["hit_count"]), "inline": True})
    if payload.get("message"):
        embed["fields"].append({"name": "Info", "value": payload["message"], "inline": False})

    return {"embeds": [embed]}


async def send_webhook(payload: dict):
    """Kirim notifikasi ke webhook URL yang dikonfigurasi (retry 3x)."""
    settings = load_settings()
    url = settings.get("webhook_url", "").strip()
    if not url:
        return

    headers = {"Content-Type": "application/json"}
    headers.update(settings.get("webhook_headers", {}))

    # ── Deteksi platform & format payload ──────────────────────────────────────
    is_discord = "discord.com/api/webhooks" in url or "discordapp.com" in url
    is_slack   = "hooks.slack.com" in url

    if is_discord:
        body = _format_discord_payload(payload)
    elif is_slack:
        # Slack incoming webhook format
        event = payload.get("event", "EVENT")
        ip    = payload.get("ip", "N/A")
        sig   = payload.get("signature", "")
        body  = {
            "text": f"*{event}* — IP: `{ip}`\n>{sig}"
        }
    else:
        # Generic JSON — Telegram, custom endpoint, dll
        body = payload

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    result_entry = {"timestamp": ts, "url": url, "status": None, "error": None}

    for attempt in range(1, 4):
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(url, json=body, headers=headers)
                result_entry["status"] = r.status_code
                if r.status_code < 400:
                    log.info(f"Webhook OK [{r.status_code}]: {url}")
                    break
                else:
                    log.warning(f"Webhook gagal [{r.status_code}] attempt {attempt}: {r.text[:200]}")
        except Exception as e:
            result_entry["error"] = str(e)
            log.error(f"Webhook error attempt {attempt}: {e}")
            await asyncio.sleep(2 ** attempt)

    webhook_log.appendleft(result_entry)


# ─── iptables Helpers (untuk unblock dari dashboard) ─────────────────────────
def _ipt_unblock(ip: str) -> tuple[bool, str]:
    """Hapus rule iptables/ip6tables untuk IP dari chain SURICATA_BLOCK."""
    # Deteksi IPv4 atau IPv6
    try:
        version = ipaddress.ip_address(ip).version
    except ValueError:
        version = 4
    
    cmd = "iptables" if version == 4 else "ip6tables"
    result = subprocess.run(
        [cmd, "-D", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )
    return result.returncode == 0, result.stderr.strip()


# ─── State Sync Helper ────────────────────────────────────────────────────────
def update_state_unblock(ip: str):
    """Hapus IP dari alert_counts.json dan reset counter-nya."""
    if not os.path.exists(ALERT_COUNTS):
        return
    try:
        with open(ALERT_COUNTS, "r") as f:
            data = json.load(f)

        current_blocked = set(data.get("blocked_ips", []))
        current_blocked.discard(ip)
        data["blocked_ips"] = list(current_blocked)

        # Reset counter jadi 0 agar tidak langsung diblok lagi
        if ip in data.get("alert_counts", {}):
            data["alert_counts"][ip] = 0

        with open(ALERT_COUNTS, "w") as f:
            json.dump(data, f)
    except Exception as e:
        log.error(f"Gagal update state unblock: {e}")


def load_initial_blocked():
    """Load blocked IPs dari state file + metadata dari log."""
    global blocked_ips, alert_counts
    if not os.path.exists(ALERT_COUNTS):
        return

    try:
        with open(ALERT_COUNTS, "r") as f:
            data = json.load(f)

        saved_counts = data.get("alert_counts", {})
        for k, v in saved_counts.items():
            alert_counts[k] = v

        blocked_set = set(data.get("blocked_ips", []))
        if not blocked_set:
            return

        # Cari metadata dari log file
        meta_map = {}
        if os.path.exists(BLOCKED_LOG):
            with open(BLOCKED_LOG, "r") as f:
                for line in reversed(f.readlines()):
                    parts = line.strip().split(" | ")
                    if len(parts) >= 4 and parts[1] == "BLOCKED":
                        ts, _, ip, sig = parts[0], parts[1], parts[2], parts[3]
                        if ip in blocked_set and ip not in meta_map:
                            meta_map[ip] = {"ts": ts, "sig": sig}

        new_list = []
        for ip in blocked_set:
            meta = meta_map.get(ip, {"ts": "Unknown", "sig": "Unknown"})
            new_list.append({
                "ip":        ip,
                "timestamp": meta["ts"],
                "signature": meta["sig"],
                "count":     alert_counts.get(ip, 0),
            })

        blocked_ips = new_list
        stats["total_blocked"] = len(blocked_ips)
        log.info(f"Loaded {len(blocked_ips)} blocked IPs from state.")

    except Exception as e:
        log.error(f"Gagal load initial state: {e}")


# ─── Eve.json Tail Task ───────────────────────────────────────────────────────
async def tail_eve():
    """
    Background task: tail eve.json dan tampilkan alert di dashboard.
    CATATAN: Blocking iptables dilakukan oleh auto_block.py, bukan di sini.
             Dashboard hanya membaca untuk tampilan Live Feed.
    """
    while not os.path.exists(EVE_LOG_PATH):
        log.info(f"Menunggu {EVE_LOG_PATH} ...")
        await asyncio.sleep(5)

    log.info(f"Mulai membaca {EVE_LOG_PATH}")

    async with aiofiles.open(EVE_LOG_PATH, "r") as f:
        await f.seek(0, 2)  # Loncat ke akhir file
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

            settings  = load_settings()
            severity  = event.get("alert", {}).get("severity", 99)
            src_ip    = event.get("src_ip", "")
            signature = event.get("alert", {}).get("signature", "N/A")
            category  = event.get("alert", {}).get("category", "N/A")
            ts        = event.get("timestamp", datetime.now(timezone.utc).isoformat())

            if severity > settings.get("severity", 2):
                continue

            # Update stats & alert counts (1 sumber: tail_eve saja, bukan internal_event)
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

            # Broadcast ke UI (live feed)
            await broadcast(alert_payload)

            # Kirim webhook untuk high/medium severity (1 atau 2) pertama kali
            if severity <= 2 and count == 1:
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
    load_initial_blocked()
    load_whitelist()
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
    if x_token != secret and x_token != "levi_token":
        raise HTTPException(status_code=403, detail="Invalid token")

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
async def login(req: LoginRequest):
    if req.username == DASHBOARD_USER and req.password == DASHBOARD_PASS:
        # Kirim webhook notifikasi login sukses
        asyncio.create_task(send_webhook({
            "event": "LOGIN",
            "message": f"Waktu Login: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        }))
        return {"status": "ok", "token": "levi_token"}
    raise HTTPException(status_code=401, detail="Username atau password salah!")


# ─── Routes ───────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index():
    async with aiofiles.open("static/index.html", "r", encoding="utf-8") as f:
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
        "top_attackers": sorted(
            [{"ip": k, "count": v} for k, v in alert_counts.items()],
            key=lambda x: x["count"], reverse=True
        )[:10],
    }


@app.get("/api/blocked")
async def get_blocked():
    return blocked_ips


# ─── Dynamic Whitelist ────────────────────────────────────────────────────────
WHITELIST_FILE = "whitelist.json"
dynamic_whitelist = set()

def load_whitelist():
    global dynamic_whitelist
    try:
        if os.path.exists(WHITELIST_FILE):
            with open(WHITELIST_FILE, "r") as f:
                dynamic_whitelist = set(json.load(f))
    except Exception as e:
        log.error(f"Gagal load whitelist: {e}")

def save_whitelist():
    try:
        with open(WHITELIST_FILE, "w") as f:
            json.dump(list(dynamic_whitelist), f)
    except Exception as e:
        log.error(f"Gagal simpan whitelist: {e}")

@app.get("/api/whitelist")
async def get_whitelist():
    return list(dynamic_whitelist)

@app.post("/api/whitelist/{ip}")
async def add_whitelist(ip: str):
    dynamic_whitelist.add(ip)
    save_whitelist()
    asyncio.create_task(send_webhook({
        "event": "WHITELIST_ADD",
        "ip": ip,
        "message": f"IP {ip} telah dimasukkan ke dalam Whitelist secara manual."
    }))
    return {"status": "ok"}

@app.delete("/api/whitelist/{ip}")
async def remove_whitelist(ip: str):
    dynamic_whitelist.discard(ip)
    save_whitelist()
    asyncio.create_task(send_webhook({
        "event": "WHITELIST_REMOVE",
        "ip": ip,
        "message": f"IP {ip} telah dihapus dari Whitelist secara manual."
    }))
    return {"status": "ok"}


@app.post("/api/unblock/{ip}")
async def unblock_ip_endpoint(ip: str, _=Depends(verify_token)):
    """
    Unblock IP: hapus dari iptables SURICATA_BLOCK chain,
    update memory state, dan sync ke auto_block via file.
    """
    global blocked_ips

    # Hapus dari iptables
    ok, err = _ipt_unblock(ip)
    if not ok:
        log.warning(f"iptables unblock {ip} mungkin tidak ada: {err}")
        # Tetap lanjutkan cleanup state meskipun rule tidak ditemukan

    # Update memory
    blocked_ips = [b for b in blocked_ips if b["ip"] != ip]
    stats["total_blocked"] = len(blocked_ips)

    # Sync ke auto_block.py via state file
    update_state_unblock(ip)

    await broadcast({"type": "unblocked", "ip": ip})
    log.info(f"🔓 Unblocked: {ip}")
    
    asyncio.create_task(send_webhook({
        "event": "UNBLOCKED",
        "ip": ip,
        "message": f"IP {ip} telah dibebaskan dari blokir (Unblock) secara manual melalui Dashboard."
    }))
    
    return {"status": "ok", "ip": ip, "iptables_ok": ok}


@app.get("/api/alerts")
async def get_alerts(limit: int = 100):
    return list(recent_alerts)[:limit]


@app.get("/api/settings")
async def get_settings(_=Depends(verify_token)):
    s = load_settings()
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
        "message":   "Test webhook dari Suricata Auto Block Dashboard",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await send_webhook(payload)
    logs = list(webhook_log)
    return {"status": "sent", "log": logs[:1]}


@app.get("/api/webhook/log")
async def get_webhook_log(_=Depends(verify_token)):
    return list(webhook_log)


# ─── Internal endpoint (dipanggil oleh auto_block.py) ────────────────────────
@app.post("/internal/event")
async def internal_event(request: Request):
    """
    Endpoint internal untuk menerima event dari auto_block.py.
    - type="blocked": update blocked_ips, kirim webhook, broadcast UI
    - type="alert": DIABAIKAN (tail_eve() sudah menangani dari eve.json langsung)
    """
    try:
        data = await request.json()
        event_type = data.get("type", "alert")

        if event_type == "blocked":
            src_ip    = data.get("src_ip", "")   # FIX: "src_ip" bukan "ip"
            signature = data.get("signature", "N/A")
            count     = data.get("count", 0)
            ts        = data.get("timestamp", datetime.now(timezone.utc).isoformat())

            # Hindari duplikat
            if src_ip and not any(b["ip"] == src_ip for b in blocked_ips):
                blocked_ips.insert(0, {
                    "ip":        src_ip,
                    "timestamp": ts,
                    "signature": signature,
                    "count":     count,
                })
                stats["total_blocked"] += 1

                # Broadcast ke UI
                await broadcast({
                    "type":      "blocked",
                    "src_ip":    src_ip,
                    "signature": signature,
                    "count":     count,
                    "timestamp": ts,
                })

                # Kirim webhook notifikasi
                await send_webhook({
                    "event":     "BLOCKED",
                    "ip":        src_ip,
                    "signature": signature,
                    "severity":  data.get("severity"),
                    "hit_count": count,
                    "timestamp": ts,
                })

        # type="alert" → tidak perlu diproses, tail_eve() sudah menangani

        return {"status": "ok"}
    except Exception as e:
        log.error(f"internal_event error: {e}")
        return {"status": "error", "detail": str(e)}
