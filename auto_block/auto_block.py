#!/usr/bin/env python3
"""
auto_block.py — Auto Firewall Blocking berbasis Suricata eve.json
Membaca log Suricata real-time, memblok IP via UFW, dan
mengirim event ke dashboard via HTTP internal.
"""

import asyncio
import json
import logging
import os
import signal
import subprocess
import sys
import time
import ipaddress
from collections import defaultdict
from datetime import datetime, timezone

import httpx

# ─── Config ───────────────────────────────────────────────────────────────────
EVE_LOG_PATH    = os.getenv("EVE_LOG_PATH",    "/var/log/suricata/eve.json")
BLOCK_THRESHOLD = int(os.getenv("BLOCK_THRESHOLD", "3"))
CHECK_INTERVAL  = int(os.getenv("CHECK_INTERVAL",  "10"))
ALERT_SEVERITY  = int(os.getenv("ALERT_SEVERITY",  "2"))
DASHBOARD_URL   = os.getenv("DASHBOARD_URL",   "http://127.0.0.1:8080")
BLOCKED_LOG     = "/app/blocked_ips.log"
STATE_FILE      = "/app/alert_counts.json"

# IP statis yang tidak boleh diblok
WHITELIST_IPS = {"127.0.0.1", "::1", "0.0.0.0"}

# Subnet private yang tidak boleh diblok (RFC 1918)
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

def is_whitelisted(ip: str) -> bool:
    if ip in WHITELIST_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("auto_block")

# ─── State ────────────────────────────────────────────────────────────────────
alert_counts: dict = defaultdict(int)
blocked_ips:  set  = set()
running = True


def load_state():
    """Load alert_counts dan blocked_ips dari file (bertahan saat restart)."""
    global alert_counts, blocked_ips
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                data = json.load(f)
            alert_counts = defaultdict(int, data.get("alert_counts", {}))
            blocked_ips  = set(data.get("blocked_ips", []))
            log.info(f"State di-load: {len(alert_counts)} IP tercatat, {len(blocked_ips)} diblok")
        except Exception as e:
            log.warning(f"Gagal load state: {e}")


def save_state():
    """Simpan alert_counts dan blocked_ips ke file."""
    try:
        with open(STATE_FILE, "w") as f:
            json.dump({
                "alert_counts": dict(alert_counts),
                "blocked_ips":  list(blocked_ips),
            }, f)
    except Exception as e:
        log.warning(f"Gagal simpan state: {e}")


def handle_exit(signum, frame):
    global running
    log.info("Menghentikan auto_block...")
    save_state()
    running = False

signal.signal(signal.SIGTERM, handle_exit)
signal.signal(signal.SIGINT,  handle_exit)


# ─── Kirim event ke Dashboard ─────────────────────────────────────────────────
def notify_dashboard(payload: dict):
    """Kirim event ke endpoint internal dashboard (non-blocking, best-effort)."""
    try:
        with httpx.Client(timeout=3) as client:
            client.post(f"{DASHBOARD_URL}/internal/event", json=payload)
    except Exception:
        pass  # Dashboard mungkin belum ready, tidak perlu fatal


# ─── UFW Blocking ────────────────────────────────────────────────────────────
def is_ufw_available() -> bool:
    return subprocess.run(["which", "ufw"], capture_output=True).returncode == 0


def block_ip(ip: str, signature: str, count: int) -> bool:
    if ip in blocked_ips or is_whitelisted(ip):
        return False

    try:
        check = subprocess.run(["ufw", "status", "numbered"], capture_output=True, text=True)
        if ip in check.stdout:
            blocked_ips.add(ip)
            return False

        result = subprocess.run(
            ["ufw", "deny", "from", ip, "to", "any"],
            capture_output=True, text=True
        )

        if result.returncode == 0:
            blocked_ips.add(ip)
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            log.warning(f"🔒 DIBLOK: {ip} | {signature}")

            with open(BLOCKED_LOG, "a") as f:
                f.write(f"{ts} | BLOCKED | {ip} | {signature}\n")

            # Kirim ke dashboard
            notify_dashboard({
                "type":      "blocked",
                "src_ip":    ip,
                "signature": signature,
                "count":     count,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return True
        else:
            log.error(f"Gagal blok {ip}: {result.stderr.strip()}")
            return False
    except Exception as e:
        log.error(f"Error memblok {ip}: {e}")
        return False


# ─── Tail eve.json ────────────────────────────────────────────────────────────
def tail_eve_json(filepath: str):
    while not os.path.exists(filepath):
        log.info(f"Menunggu {filepath} ...")
        time.sleep(5)

    log.info(f"Membaca: {filepath}")
    with open(filepath, "r") as f:
        f.seek(0, 2)
        while running:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue
            line = line.strip()
            if line:
                yield line


# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    log.info("=" * 55)
    log.info("  Suricata Auto Block Service")
    log.info(f"  Threshold    : {BLOCK_THRESHOLD} alerts")
    log.info(f"  Min Severity : {ALERT_SEVERITY}")
    log.info(f"  Dashboard    : {DASHBOARD_URL}")
    log.info("=" * 55)

    load_state()

    dry_run = not is_ufw_available()
    if dry_run:
        log.warning("UFW tidak ditemukan — DRY RUN mode (tidak ada blok nyata)")
    else:
        subprocess.run(["ufw", "--force", "enable"], capture_output=True)

    for line in tail_eve_json(EVE_LOG_PATH):
        if not running:
            break
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") != "alert":
            continue

        severity  = event.get("alert", {}).get("severity", 99)
        src_ip    = event.get("src_ip", "")
        signature = event.get("alert", {}).get("signature", "N/A")

        if severity > ALERT_SEVERITY or not src_ip or is_whitelisted(src_ip):
            continue

        alert_counts[src_ip] += 1
        count = alert_counts[src_ip]

        log.info(f"⚠  [{severity}] {src_ip} | hit {count}/{BLOCK_THRESHOLD} | {signature}")

        # Kirim alert ke dashboard
        notify_dashboard({
            "type":      "alert",
            "src_ip":    src_ip,
            "signature": signature,
            "category":  event.get("alert", {}).get("category", ""),
            "severity":  severity,
            "count":     count,
            "threshold": BLOCK_THRESHOLD,
            "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
        })

        # Blok jika threshold tercapai
        if count >= BLOCK_THRESHOLD and src_ip not in blocked_ips:
            if dry_run:
                log.warning(f"[DRY-RUN] Blok: {src_ip}")
                blocked_ips.add(src_ip)
            else:
                block_ip(src_ip, signature, count)

    log.info("Auto block selesai.")


if __name__ == "__main__":
    main()
