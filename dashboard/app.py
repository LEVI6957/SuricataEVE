"""
app.py — Suricata Auto Block Dashboard
FastAPI backend: REST API + WebSocket real-time + Webhook outbound

Author: Levi (github.com/LEVI6957)
"""

import asyncio
import ipaddress
import hashlib
import json
import logging
import os
import subprocess
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Optional

import secrets
import urllib.request
import urllib.error
from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect,
    HTTPException, Request, Header, Depends
)
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ─── Config ───────────────────────────────────────────────────────────────────
EVE_LOG_PATH   = os.getenv("EVE_LOG_PATH",   "/var/log/suricata/eve.json")
BLOCKED_LOG    = os.getenv("BLOCKED_LOG",    "/app/blocked_ips.log")
ALERT_COUNTS   = os.getenv("ALERT_COUNTS",   "/app/alert_counts.json")
SETTINGS_FILE  = os.getenv("SETTINGS_FILE",  "/app/settings.json")
WHITELIST_FILE = os.getenv("WHITELIST_FILE", "/app/whitelist.json")
IPTABLES_CHAIN = "SURICATA_BLOCK"

# ─── Kredensial Login ───────────────────────────────────────────────────────────
# Kredensial dibaca/disimpan dari settings.json (Setup Wizard)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("dashboard")

# ─── In-memory State ──────────────────────────────────────────────────────────
recent_alerts: deque = deque(maxlen=200)
blocked_ips: list[dict] = []
alert_counts: dict = {}  # Format: {"ip": {"count": X, "last_seen": timestamp}}
stats = {"total_alerts": 0, "total_blocked": 0, "start_time": time.time()}
ws_clients: list[WebSocket] = []
webhook_log: deque = deque(maxlen=50)

# ─── Dynamic Whitelist ────────────────────────────────────────────────────────
# Harus didefinisikan sebelum _parse_alert_line yang mereferensikannya
dynamic_whitelist: set = set()


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
            "severity": 3,
            "interval": 1,
            "secret_token": "",
            "telegram_chat_id": "",
        }


def save_settings(data: dict):
    tmp_file = SETTINGS_FILE + ".tmp"
    with open(tmp_file, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_file, SETTINGS_FILE)


# ─── Whitelist Helper ─────────────────────────────────────────────────────────
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
        tmp_file = WHITELIST_FILE + ".tmp"
        with open(tmp_file, "w") as f:
            json.dump(list(dynamic_whitelist), f)
        os.replace(tmp_file, WHITELIST_FILE)
    except Exception as e:
        log.error(f"Gagal simpan whitelist: {e}")


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

    color = {
        "BLOCKED":          0xEF4444,
        "HIGH_ALERT":       0xF59E0B,
        "TEST":             0x6366F1,
        "WHITELIST_ADD":    0x22C55E,
        "WHITELIST_REMOVE": 0xF97316,
        "UNBLOCKED":        0x3B82F6,
        "LOGIN":            0xFCD34D,
        "LOGOUT":           0x9CA3AF,
    }.get(event, 0x64748B)

    title_icon = {
        "BLOCKED":          "\U0001f512 IP Diblok",
        "HIGH_ALERT":       "\u26a0\ufe0f High Alert",
        "TEST":             "\U0001f9ea Test Webhook",
        "WHITELIST_ADD":    "\u2705 Masuk Whitelist",
        "WHITELIST_REMOVE": "\u274c Keluar Whitelist",
        "UNBLOCKED":        "\U0001f513 IP Dibebaskan",
        "LOGIN":            "\U0001f389\U0001f60e\U0001f525 BOS LOGIN CUI!! \U0001f525\U0001f60e\U0001f389",
        "LOGOUT":           "YAAAHHH BOS LOG OUT SAD!!! \U0001f62d\U0001f62d\U0001f62d\U0001f494\U0001f494",
    }.get(event, f"\U0001f4e1 {event}")

    embed = {
        "title": title_icon,
        "color": color,
        "timestamp": ts if ts else datetime.now(timezone.utc).isoformat(),
        "footer": {"text": "Suricata Auto Block Dashboard"},
        "fields": [],
    }

    if ip and ip != "N/A":
        ip_label = "IP Penyerang" if event in ["BLOCKED", "HIGH_ALERT"] else "Alamat IP"
        embed["fields"].append({"name": ip_label, "value": f"`{ip}`", "inline": True})
    if sig and sig != "N/A":
        embed["fields"].append({"name": "Signature", "value": sig[:256], "inline": False})
    if sev and sev != "N/A":
        embed["fields"].append({"name": "Severity", "value": str(sev), "inline": True})
    if payload.get("hit_count"):
        embed["fields"].append({"name": "Hit Count", "value": str(payload["hit_count"]), "inline": True})
    if payload.get("message"):
        embed["fields"].append({"name": "Info", "value": payload["message"], "inline": False})

    return {"embeds": [embed]}


def _format_telegram_payload(payload: dict, chat_id: str) -> dict:
    """Format payload khusus untuk Telegram Bot API sendMessage."""
    event = payload.get("event", "EVENT")
    ip    = payload.get("ip", "")
    sig   = payload.get("signature", "")
    sev   = payload.get("severity", "")
    msg   = payload.get("message", "")
    ts    = payload.get("timestamp", datetime.now(timezone.utc).isoformat())

    icon = {
        "BLOCKED":          "\U0001f512",
        "HIGH_ALERT":       "\u26a0\ufe0f",
        "TEST":             "\U0001f9ea",
        "WHITELIST_ADD":    "\u2705",
        "WHITELIST_REMOVE": "\u274c",
        "UNBLOCKED":        "\U0001f513",
        "LOGIN":            "\U0001f389",
        "LOGOUT":           "\U0001f44b",
    }.get(event, "\U0001f4e1")

    lines = [f"{icon} <b>Suricata \u2014 {event}</b>"]
    if ip:  lines.append(f"\U0001f310 IP: <code>{ip}</code>")
    if sig: lines.append(f"\U0001f4cb Signature: {sig[:200]}")
    if sev: lines.append(f"\U0001f3af Severity: {sev}")
    if payload.get("hit_count"): lines.append(f"\U0001f522 Hit Count: {payload['hit_count']}")
    if msg: lines.append(f"\u2139\ufe0f {msg}")
    lines.append(f"\U0001f550 {ts}")

    return {
        "chat_id":    chat_id,
        "text":       "\n".join(lines),
        "parse_mode": "HTML",
    }


async def send_webhook(payload: dict):
    """Kirim notifikasi ke webhook URL yang dikonfigurasi (retry 3x)."""
    settings = load_settings()
    url = settings.get("webhook_url", "").strip()
    if not url:
        return

    headers = {"Content-Type": "application/json"}
    headers.update(settings.get("webhook_headers", {}))

    is_discord  = "discord.com/api/webhooks" in url or "discordapp.com" in url
    is_slack    = "hooks.slack.com" in url
    is_telegram = "api.telegram.org" in url

    if is_discord:
        body = _format_discord_payload(payload)
    elif is_slack:
        event = payload.get("event", "EVENT")
        ip    = payload.get("ip", "N/A")
        sig   = payload.get("signature", "")
        body  = {"text": f"*{event}* \u2014 IP: `{ip}`\n>{sig}"}
    elif is_telegram:
        chat_id = settings.get("telegram_chat_id", "").strip()
        if not chat_id:
            log.warning("Telegram webhook: telegram_chat_id belum diset di settings!")
            return
        body = _format_telegram_payload(payload, chat_id)
    else:
        body = payload

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    result_entry: dict = {"timestamp": ts, "url": url, "status": None, "error": None}

    req = urllib.request.Request(url, data=json.dumps(body).encode('utf-8'), headers=headers, method="POST")

    for attempt in range(1, 4):
        try:
            def _do_post():
                with urllib.request.urlopen(req, timeout=10) as response:
                    return response.status, response.read().decode('utf-8')
            
            status, text = await asyncio.to_thread(_do_post)
            result_entry["status"] = status
            if status < 400:
                log.info(f"Webhook OK [{status}]: {url}")
                break
            else:
                log.warning(f"Webhook gagal [{status}] attempt {attempt}: {text[:200]}")
        except urllib.error.HTTPError as e:
            result_entry["status"] = e.code
            result_entry["error"] = str(e)
            err_text = ""
            try:
                err_text = e.read().decode('utf-8')
            except:
                pass
            log.warning(f"Webhook gagal [{e.code}] attempt {attempt}: {err_text[:200]}")
            await asyncio.sleep(2 ** attempt)
        except Exception as e:
            result_entry["error"] = str(e)
            log.error(f"Webhook error attempt {attempt}: {e}")
            await asyncio.sleep(2 ** attempt)

    webhook_log.appendleft(result_entry)


# ─── iptables Helpers ─────────────────────────────────────────────────────────
def _ipt_unblock(ip: str) -> tuple[bool, str]:
    """Hapus rule iptables/ip6tables untuk IP dari chain SURICATA_BLOCK."""
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


def _ipt_block_ip(ip: str) -> bool:
    """Block IP via iptables langsung dari dashboard (untuk brute force login)."""
    try:
        version = ipaddress.ip_address(ip).version
    except ValueError:
        version = 4
    cmd = "iptables" if version == 4 else "ip6tables"
    result = subprocess.run(
        [cmd, "-I", IPTABLES_CHAIN, "1", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )
    return result.returncode == 0


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
        if ip in data.get("alert_counts", {}):
            if isinstance(data["alert_counts"][ip], dict):
                data["alert_counts"][ip]["count"] = 0
            else:
                data["alert_counts"][ip] = 0
        with open(ALERT_COUNTS, "w") as f:
            json.dump(data, f)
    except Exception as e:
        log.error(f"Gagal update state unblock: {e}")


def load_initial_blocked():
    """Load blocked IPs dari state file + metadata dari log."""
    global blocked_ips
    if not os.path.exists(ALERT_COUNTS):
        return
    try:
        with open(ALERT_COUNTS, "r") as f:
            data = json.load(f)

        saved_counts = data.get("alert_counts", {})
        for k, v in saved_counts.items():
            if isinstance(v, int):
                alert_counts[k] = {"count": v, "last_seen": time.time()}
            else:
                alert_counts[k] = v

        blocked_set = set(data.get("blocked_ips", []))
        if not blocked_set:
            return

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
                "count":     alert_counts.get(ip, {}).get("count", 0) if isinstance(alert_counts.get(ip), dict) else alert_counts.get(ip, 0),
            })

        blocked_ips = new_list
        stats["total_blocked"] = len(blocked_ips)
        log.info(f"Loaded {len(blocked_ips)} blocked IPs from state.")
    except Exception as e:
        log.error(f"Gagal load initial state: {e}")


# ─── Eve.json Parser ──────────────────────────────────────────────────────────
def _parse_alert_line(line: str, settings: dict, check_whitelist: bool = False) -> Optional[dict]:
    """Parse satu baris eve.json dan kembalikan alert_payload jika valid, else None."""
    line = line.strip()
    if not line:
        return None
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return None

    if event.get("event_type") != "alert":
        return None

    severity  = event.get("alert", {}).get("severity", 99)
    src_ip    = event.get("src_ip", "")
    signature = event.get("alert", {}).get("signature", "N/A")
    category  = event.get("alert", {}).get("category", "N/A")
    ts        = event.get("timestamp", datetime.now(timezone.utc).isoformat())

    if severity > settings.get("severity", 3):
        return None

    if check_whitelist and src_ip in dynamic_whitelist:
        return None

    return {
        "type":      "alert",
        "src_ip":    src_ip,
        "signature": signature,
        "category":  category,
        "severity":  severity,
        "timestamp": ts,
    }


def _read_last_bytes(filepath: str, num_bytes: int) -> list[str]:
    """Baca num_bytes terakhir dari file besar secara efisien."""
    with open(filepath, "rb") as f:
        f.seek(0, 2)
        file_size = f.tell()
        read_size = min(num_bytes, file_size)
        f.seek(-read_size, 2)
        raw = f.read(read_size)
    return raw.decode("utf-8", errors="replace").splitlines()


# ─── Historical Alert Loader ──────────────────────────────────────────────────
async def load_historical_alerts():
    """Baca 300MB terakhir eve.json untuk muat alert 3 hari terakhir."""
    if not os.path.exists(EVE_LOG_PATH):
        return

    cutoff = datetime.now(timezone.utc) - timedelta(days=3)
    settings = load_settings()
    loaded = 0

    log.info("Memuat alert historis 3 hari terakhir (baca 300MB terakhir eve.json)...")
    temp_alerts: list[dict] = []

    READ_BYTES = 300 * 1024 * 1024  # 300 MB
    try:
        lines = await asyncio.get_event_loop().run_in_executor(
            None, _read_last_bytes, EVE_LOG_PATH, READ_BYTES
        )
    except Exception as e:
        log.error(f"Gagal baca eve.json untuk historis: {e}")
        return

    for line in lines:
        payload = _parse_alert_line(line, settings, check_whitelist=False)
        if not payload:
            continue
        try:
            ts_dt = datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00"))
            if ts_dt < cutoff:
                continue
        except Exception:
            pass

        stats["total_alerts"] += 1
        src_ip = payload.get("src_ip", "")
        if src_ip not in alert_counts: alert_counts[src_ip] = {"count": 0, "last_seen": time.time()}
        alert_counts[src_ip]["count"] += 1
        alert_counts[src_ip]["last_seen"] = time.time()
        payload["count"] = alert_counts[src_ip]["count"]
        payload["threshold"] = settings.get("threshold", 3)
        temp_alerts.append(payload)
        loaded += 1

    for p in temp_alerts:
        recent_alerts.appendleft(p)

    log.info(f"Selesai memuat {loaded} alert historis ke Live Feed.")


# ─── Eve.json Live Tail Task ──────────────────────────────────────────────────
async def tail_eve():
    """
    Background task: tail eve.json dan tampilkan alert di dashboard.
    Blocking iptables dilakukan oleh auto_block.py, bukan di sini.
    """
    while not os.path.exists(EVE_LOG_PATH):
        log.info(f"Menunggu {EVE_LOG_PATH} ...")
        await asyncio.sleep(5)

    await load_historical_alerts()

    log.info(f"Mulai memantau (tail) {EVE_LOG_PATH} untuk alert baru...")

    with open(EVE_LOG_PATH, "r") as f:
        f.seek(0, 2)
        while True:
            line = await asyncio.to_thread(f.readline)
            if not line:
                settings = load_settings()
                poll_interval = max(0.1, settings.get("interval", 1))
                await asyncio.sleep(poll_interval)
                continue

            settings = load_settings()
            payload = _parse_alert_line(line, settings, check_whitelist=True)
            if not payload:
                continue

            stats["total_alerts"] += 1
            src_ip = payload.get("src_ip", "")
            if src_ip not in alert_counts: alert_counts[src_ip] = {"count": 0, "last_seen": time.time()}
            alert_counts[src_ip]["count"] += 1
            alert_counts[src_ip]["last_seen"] = time.time()
            payload["count"] = alert_counts[src_ip]["count"]
            payload["threshold"] = settings.get("threshold", 3)

            recent_alerts.appendleft(payload)
            await broadcast(payload)

            if payload["severity"] <= 2 and payload["count"] == 1:
                await send_webhook({
                    "event":     "HIGH_ALERT",
                    "ip":        payload["src_ip"],
                    "signature": payload["signature"],
                    "category":  payload["category"],
                    "severity":  payload["severity"],
                    "timestamp": payload["timestamp"],
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


# ─── Auth Token Verification ─────────────────────────────────────────────────
def verify_token(x_token: Optional[str] = Header(default=None)):
    settings = load_settings()
    secret = settings.get("secret_token", "").strip()
    if not secret:
        raise HTTPException(status_code=401, detail="Dashboard belum di-setup (secret kosong).")
    if x_token != secret:
        raise HTTPException(status_code=403, detail="Invalid token")


# ─── Brute Force Protection ──────────────────────────────────────────────────
login_fail_tracker: dict = defaultdict(lambda: {"count": 0, "blocked": False})
LOGIN_MAX_ATTEMPTS = 5


class LoginRequest(BaseModel):
    username: str
    password: str

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

@app.get("/api/setup/status")
async def setup_status():
    settings = load_settings()
    admin_user = settings.get("admin_username")
    admin_pass = settings.get("admin_password_hash")
    if not admin_user or not admin_pass:
        return {"setup_required": True}
    return {"setup_required": False}

@app.post("/api/setup")
async def setup(req: LoginRequest):
    settings = load_settings()
    if settings.get("admin_username") and settings.get("admin_password_hash"):
        raise HTTPException(status_code=400, detail="Setup sudah dilakukan.")
    
    settings["admin_username"] = req.username
    settings["admin_password_hash"] = hash_password(req.password)
    if not settings.get("secret_token"):
        settings["secret_token"] = secrets.token_hex(32)
    save_settings(settings)
    return {"status": "ok", "message": "Setup berhasil"}

@app.post("/api/login")
async def login(req: LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"

    tracker = login_fail_tracker[client_ip]
    if tracker["blocked"]:
        raise HTTPException(status_code=429, detail="IP Anda diblokir karena terlalu banyak percobaan login gagal.")

    settings = load_settings()
    admin_user = settings.get("admin_username")
    admin_pass = settings.get("admin_password_hash")

    if not admin_user or not admin_pass:
        raise HTTPException(status_code=500, detail="Dashboard belum di-setup.")

    if req.username == admin_user and hash_password(req.password) == admin_pass:
        login_fail_tracker[client_ip] = {"count": 0, "blocked": False}
        asyncio.create_task(send_webhook({
            "event": "LOGIN",
            "message": f"Login berhasil dari {client_ip} \u2014 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        }))
        
        secret = settings.get("secret_token", "").strip()
        if not secret:
            secret = secrets.token_hex(32)
            settings["secret_token"] = secret
            save_settings(settings)
            
        return {"status": "ok", "token": secret}

    # OOM Protection
    if len(login_fail_tracker) > 1000:
        login_fail_tracker.clear()

    tracker["count"] += 1
    attempts_left = LOGIN_MAX_ATTEMPTS - tracker["count"]
    log.warning(f"Login gagal dari {client_ip} \u2014 percobaan {tracker['count']}/{LOGIN_MAX_ATTEMPTS}")

    if tracker["count"] >= LOGIN_MAX_ATTEMPTS:
        tracker["blocked"] = True
        log.warning(f"BRUTE FORCE TERDETEKSI! IP: {client_ip}")

        if client_ip in dynamic_whitelist:
            log.warning(f"{client_ip} ada di whitelist \u2014 tidak diblokir via iptables.")
            raise HTTPException(
                status_code=429,
                detail="Terlalu banyak percobaan login gagal! Tunggu sebelum mencoba lagi."
            )

        ok = _ipt_block_ip(client_ip)
        if not ok:
            log.warning(f"Gagal block {client_ip} via iptables (brute force login)")
        ts = datetime.now(timezone.utc).isoformat()

        if not any(b["ip"] == client_ip for b in blocked_ips):
            blocked_ips.insert(0, {
                "ip":        client_ip,
                "timestamp": ts,
                "signature": "BRUTE FORCE \u2014 Login Dashboard (5x Gagal)",
                "count":     LOGIN_MAX_ATTEMPTS,
            })
            stats["total_blocked"] += 1

        await broadcast({
            "type":      "blocked",
            "src_ip":    client_ip,
            "signature": "BRUTE FORCE \u2014 Login Dashboard (5x Gagal)",
            "count":     LOGIN_MAX_ATTEMPTS,
            "timestamp": ts,
        })

        await send_webhook({
            "event":     "BLOCKED",
            "ip":        client_ip,
            "signature": "BRUTE FORCE LOGIN \u2014 Dashboard (5x percobaan gagal)",
            "severity":  1,
            "hit_count": LOGIN_MAX_ATTEMPTS,
            "timestamp": ts,
        })

        raise HTTPException(
            status_code=429,
            detail=f"IP {client_ip} diblokir karena {LOGIN_MAX_ATTEMPTS}x percobaan login gagal!"
        )

    raise HTTPException(
        status_code=401,
        detail=f"Username atau password salah! Sisa percobaan: {max(0, attempts_left)}"
    )


@app.post("/api/logout", dependencies=[Depends(verify_token)])
async def logout(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    asyncio.create_task(send_webhook({
        "event": "LOGOUT",
        "message": f"Logout dari {client_ip} \u2014 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
    }))
    return {"status": "ok"}


# ─── Routes ───────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def index():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    ws_clients.append(ws)
    for alert in list(recent_alerts)[:50]:
        await ws.send_text(json.dumps(alert))
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        if ws in ws_clients:
            ws_clients.remove(ws)


@app.get("/api/stats")
async def get_stats():
    uptime_sec = int(time.time() - stats["start_time"])
    return {
        "total_alerts":   stats["total_alerts"],
        "total_blocked":  stats["total_blocked"],
        "active_clients": len(ws_clients),
        "uptime_seconds": uptime_sec,
        "top_attackers": sorted(
            [{"ip": k, "count": v.get("count", v) if isinstance(v, dict) else v} for k, v in alert_counts.items()],
            key=lambda x: x["count"], reverse=True
        )[:10],
    }


@app.get("/api/blocked")
async def get_blocked():
    return blocked_ips


@app.get("/api/alerts")
async def get_alerts(limit: int = 200):
    """Kembalikan alert historis dari memori (max 200, urutan terbaru duluan)."""
    return list(recent_alerts)[:limit]


# ─── Whitelist Routes ─────────────────────────────────────────────────────────
@app.get("/api/whitelist")
async def get_whitelist():
    return list(dynamic_whitelist)


@app.post("/api/whitelist/{ip}")
async def add_whitelist(ip: str):
    dynamic_whitelist.add(ip)
    save_whitelist()
    _ipt_unblock(ip)
    update_state_unblock(ip)
    await broadcast({"type": "unblocked", "ip": ip})
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
    alert_counts.pop(ip, None)
    asyncio.create_task(send_webhook({
        "event": "WHITELIST_REMOVE",
        "ip": ip,
        "message": f"IP {ip} telah dihapus dari Whitelist secara manual."
    }))
    return {"status": "ok"}


# ─── Unblock Route ────────────────────────────────────────────────────────────
@app.post("/api/unblock/{ip}")
async def unblock_ip_endpoint(ip: str, _=Depends(verify_token)):
    """Unblock IP: hapus dari iptables, update state, sync ke auto_block."""
    global blocked_ips
    ok, err = _ipt_unblock(ip)
    if not ok:
        log.warning(f"iptables unblock {ip} mungkin tidak ada: {err}")

    blocked_ips = [b for b in blocked_ips if b["ip"] != ip]
    stats["total_blocked"] = len(blocked_ips)
    update_state_unblock(ip)
    await broadcast({"type": "unblocked", "ip": ip})
    log.info(f"Unblocked: {ip}")
    asyncio.create_task(send_webhook({
        "event": "UNBLOCKED",
        "ip": ip,
        "message": f"IP {ip} telah dibebaskan dari blokir secara manual melalui Dashboard."
    }))
    return {"status": "ok", "ip": ip, "iptables_ok": ok}


# ─── Settings Routes ──────────────────────────────────────────────────────────
@app.get("/api/settings")
async def get_settings(_=Depends(verify_token)):
    s = load_settings()
    if s.get("secret_token"):
        s["secret_token"] = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
    return s


class SettingsUpdate(BaseModel):
    webhook_url:      Optional[str]  = None
    webhook_headers:  Optional[dict] = None
    threshold:        Optional[int]  = None
    severity:         Optional[int]  = None
    interval:         Optional[int]  = None
    secret_token:     Optional[str]  = None
    telegram_chat_id: Optional[str]  = None


@app.post("/api/settings")
async def update_settings(body: SettingsUpdate, _=Depends(verify_token)):
    s = load_settings()
    if body.webhook_url      is not None: s["webhook_url"]      = body.webhook_url
    if body.webhook_headers  is not None: s["webhook_headers"]  = body.webhook_headers
    if body.threshold        is not None: s["threshold"]        = body.threshold
    if body.severity         is not None: s["severity"]         = body.severity
    if body.interval         is not None: s["interval"]         = body.interval
    if body.telegram_chat_id is not None: s["telegram_chat_id"] = body.telegram_chat_id
    if body.secret_token and body.secret_token != "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022":
        s["secret_token"] = body.secret_token
    save_settings(s)
    return {"status": "saved"}


# ─── Webhook Test & Log Routes ────────────────────────────────────────────────
@app.post("/api/webhook/test")
async def test_webhook(_=Depends(verify_token)):
    payload = {
        "event":     "TEST",
        "message":   "Test webhook dari Suricata Auto Block Dashboard",
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
    """
    Endpoint internal untuk menerima event dari auto_block.py.
    - type=blocked: update blocked_ips, kirim webhook, broadcast UI
    - type=alert: DIABAIKAN (tail_eve() sudah menangani dari eve.json langsung)
    """
    try:
        data = await request.json()
        event_type = data.get("type", "alert")

        if event_type == "blocked":
            src_ip    = data.get("src_ip", "")
            signature = data.get("signature", "N/A")
            count     = data.get("count", 0)
            ts        = data.get("timestamp", datetime.now(timezone.utc).isoformat())

            if src_ip and not any(b["ip"] == src_ip for b in blocked_ips):
                blocked_ips.insert(0, {
                    "ip":        src_ip,
                    "timestamp": ts,
                    "signature": signature,
                    "count":     count,
                })
                stats["total_blocked"] += 1

                await broadcast({
                    "type":      "blocked",
                    "src_ip":    src_ip,
                    "signature": signature,
                    "count":     count,
                    "timestamp": ts,
                })

                await send_webhook({
                    "event":     "BLOCKED",
                    "ip":        src_ip,
                    "signature": signature,
                    "severity":  data.get("severity"),
                    "hit_count": count,
                    "timestamp": ts,
                })

        return {"status": "ok"}
    except Exception as e:
        log.error(f"internal_event error: {e}")
        return {"status": "error", "detail": str(e)}
