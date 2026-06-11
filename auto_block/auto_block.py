#!/usr/bin/env python3
"""
auto_block.py — Auto Firewall Blocking berbasis Suricata eve.json
Membaca log Suricata real-time, memblok IP via iptables (custom chain),
dan mengirim event ke dashboard via HTTP internal.

Cara kerja:
  1. Buat chain SURICATA_BLOCK di iptables (jika belum ada)
  2. Hubungkan chain ke INPUT & FORWARD
  3. Baca eve.json Suricata secara real-time (tail)
  4. Jika IP mencapai threshold alert → DROP via iptables

Author: Levi (github.com/LEVI6957)
"""

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
ALERT_SEVERITY  = int(os.getenv("ALERT_SEVERITY",  "2"))
DASHBOARD_URL   = os.getenv("DASHBOARD_URL",   "http://127.0.0.1:8080")
BLOCKED_LOG     = "/app/blocked_ips.log"
STATE_FILE      = "/app/alert_counts.json"

# Nama custom chain iptables khusus Suricata
IPTABLES_CHAIN  = "SURICATA_BLOCK"

# IP statis yang tidak boleh diblok (baca dari .env, pisahkan dengan koma)
env_whitelist = os.getenv("WHITELIST_IPS", "")
WHITELIST_IPS = {"127.0.0.1", "::1", "0.0.0.0"}
if env_whitelist:
    WHITELIST_IPS.update([ip.strip() for ip in env_whitelist.split(",") if ip.strip()])

# Dynamic whitelist dari Dashboard UI
dynamic_whitelist = set()
last_whitelist_fetch = 0

def get_dynamic_whitelist() -> set:
    global dynamic_whitelist, last_whitelist_fetch
    now = time.time()
    # Fetch setiap 10 detik agar tidak membebani dashboard
    if now - last_whitelist_fetch > 10:
        try:
            with httpx.Client(timeout=2) as client:
                res = client.get(f"{DASHBOARD_URL}/api/whitelist")
                if res.status_code == 200:
                    dynamic_whitelist = set(res.json())
                    last_whitelist_fetch = now
        except Exception:
            pass
    return dynamic_whitelist

# ─── Dynamic Settings ─────────────────────────────────────────────────────────
last_settings_fetch = 0
current_threshold = int(os.getenv("BLOCK_THRESHOLD", "3"))
current_severity = int(os.getenv("ALERT_SEVERITY", "2"))

def update_dynamic_settings():
    global current_threshold, current_severity, last_settings_fetch
    now = time.time()
    if now - last_settings_fetch > 5:  # Reload file maks setiap 5 detik
        try:
            with open("/app/settings.json", "r") as f:
                data = json.load(f)
                current_threshold = data.get("threshold", int(os.getenv("BLOCK_THRESHOLD", "3")))
                current_severity = data.get("severity", int(os.getenv("ALERT_SEVERITY", "2")))
        except Exception:
            pass
        last_settings_fetch = now

# Subnet private yang tidak boleh diblok (RFC 1918)
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    # ipaddress.ip_network("192.168.0.0/16"), # Dihapus sementara untuk testing
]

def is_whitelisted(ip: str) -> bool:
    if not ip or ip in WHITELIST_IPS:
        return True
    
    if ip in get_dynamic_whitelist():
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
last_state_mtime = 0


def load_state():
    """Load alert_counts dan blocked_ips dari file (bertahan saat restart)."""
    global alert_counts, blocked_ips, last_state_mtime
    if not os.path.exists(STATE_FILE):
        return
    try:
        mtime = os.path.getmtime(STATE_FILE)
        if mtime == last_state_mtime:
            return  # Tidak ada perubahan

        with open(STATE_FILE, "r") as f:
            data = json.load(f)

        disk_counts  = data.get("alert_counts", {})
        disk_blocked = set(data.get("blocked_ips", []))

        # Prioritas disk: jika dashboard unblock → hapus dari memory
        blocked_ips = disk_blocked

        for ip, count in disk_counts.items():
            alert_counts[ip] = count

        last_state_mtime = mtime
        log.info(f"State reload dari disk: {len(blocked_ips)} IP diblok")

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


# ─── iptables Manager ─────────────────────────────────────────────────────────
def run_ipt(args: list, ip_version: int = 4, check: bool = False) -> subprocess.CompletedProcess:
    """Jalankan perintah iptables atau ip6tables berdasarkan versi IP."""
    cmd = "iptables" if ip_version == 4 else "ip6tables"
    return subprocess.run(
        [cmd] + args,
        capture_output=True,
        text=True,
        check=check,
    )


def is_iptables_available() -> bool:
    """Cek apakah iptables tersedia di sistem."""
    result = subprocess.run(["which", "iptables"], capture_output=True)
    return result.returncode == 0


def setup_chain():
    """
    Buat custom chain SURICATA_BLOCK jika belum ada,
    lalu hubungkan ke INPUT dan FORWARD untuk IPv4 dan IPv6.
    """
    for version in [4, 6]:
        cmd_name = "iptables" if version == 4 else "ip6tables"
        # Cek apakah chain sudah ada
        check = run_ipt(["-n", "-L", IPTABLES_CHAIN], ip_version=version)
        if check.returncode != 0:
            # Buat chain baru
            run_ipt(["-N", IPTABLES_CHAIN], ip_version=version)
            log.info(f"Chain {IPTABLES_CHAIN} berhasil dibuat di {cmd_name}")
        else:
            log.info(f"Chain {IPTABLES_CHAIN} sudah ada di {cmd_name}")

        # Pastikan chain terhubung ke INPUT (hindari duplikat)
        for hook in ["INPUT", "FORWARD"]:
            check_jump = run_ipt(["-C", hook, "-j", IPTABLES_CHAIN], ip_version=version)
            if check_jump.returncode != 0:
                run_ipt(["-I", hook, "1", "-j", IPTABLES_CHAIN], ip_version=version)
                log.info(f"Chain {IPTABLES_CHAIN} dihubungkan ke {hook} di {cmd_name}")


def get_ip_version(ip: str) -> int:
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return 4


def is_ip_blocked_in_iptables(ip: str) -> bool:
    """Cek apakah IP sudah ada di chain SURICATA_BLOCK."""
    version = get_ip_version(ip)
    result = run_ipt(["-C", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"], ip_version=version)
    return result.returncode == 0


def block_ip(ip: str, signature: str, count: int) -> bool:
    """Tambahkan rule DROP untuk IP di chain SURICATA_BLOCK."""
    if ip in blocked_ips or is_whitelisted(ip):
        return False

    version = get_ip_version(ip)

    # Double-check di iptables langsung (hindari duplikat rule)
    if is_ip_blocked_in_iptables(ip):
        blocked_ips.add(ip)
        return False

    result = run_ipt(["-I", IPTABLES_CHAIN, "1", "-s", ip, "-j", "DROP"], ip_version=version)

    if result.returncode == 0:
        blocked_ips.add(ip)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        log.warning(f"🔒 DIBLOK [IPv{version}]: {ip} | {signature} | hit={count}")

        # Tulis ke log file
        try:
            with open(BLOCKED_LOG, "a") as f:
                f.write(f"{ts} | BLOCKED | {ip} | {signature}\n")
        except Exception as e:
            log.warning(f"Gagal tulis log: {e}")

        # Kirim notifikasi ke dashboard
        notify_dashboard({
            "type":      "blocked",
            "src_ip":    ip,
            "signature": signature,
            "count":     count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return True
    else:
        log.error(f"Gagal blok {ip} via IPv{version}: {result.stderr.strip()}")
        return False


def unblock_ip(ip: str) -> bool:
    """Hapus rule DROP untuk IP dari chain SURICATA_BLOCK."""
    if not is_ip_blocked_in_iptables(ip):
        blocked_ips.discard(ip)
        return False

    version = get_ip_version(ip)
    result = run_ipt(["-D", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"], ip_version=version)
    if result.returncode == 0:
        blocked_ips.discard(ip)
        log.info(f"🔓 DIBEBASKAN [iptables]: {ip}")
        return True
    else:
        log.error(f"Gagal unblock {ip}: {result.stderr.strip()}")
        return False


def list_blocked_iptables() -> list:
    """Ambil daftar IP yang diblok dari chain SURICATA_BLOCK."""
    result = run_ipt(["-n", "-L", IPTABLES_CHAIN, "--line-numbers"])
    ips = []
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            # Format: num  DROP  all  --  <src_ip>  0.0.0.0/0
            parts = line.split()
            if len(parts) >= 5 and parts[1] == "DROP":
                ips.append(parts[4])
    return ips


# ─── Tail eve.json ────────────────────────────────────────────────────────────
def tail_eve_json(filepath: str):
    """
    Tail file eve.json secara real-time.
    Tunggu hingga file ada, lalu baca baris baru terus menerus.
    """
    while not os.path.exists(filepath):
        log.info(f"Menunggu {filepath} ...")
        time.sleep(5)

    log.info(f"Membaca eve.json: {filepath}")
    with open(filepath, "r") as f:
        f.seek(0, 2)  # Loncat ke akhir file (tail mode)
        while running:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            line = line.strip()
            if not line:
                continue

            # Cek apakah state file berubah (misal unblock dari dashboard)
            if os.path.exists(STATE_FILE):
                try:
                    if os.path.getmtime(STATE_FILE) > last_state_mtime:
                        load_state()
                except OSError:
                    pass

            yield line


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    log.info("=" * 58)
    log.info("  Suricata Auto Block Service (iptables mode)")
    log.info(f"  Eve JSON     : {EVE_LOG_PATH}")
    log.info(f"  Chain        : {IPTABLES_CHAIN}")
    log.info(f"  Threshold    : {BLOCK_THRESHOLD} alerts")
    log.info(f"  Min Severity : {ALERT_SEVERITY}")
    log.info(f"  Dashboard    : {DASHBOARD_URL}")
    log.info("=" * 58)

    load_state()

    # Cek iptables tersedia
    if not is_iptables_available():
        log.critical("iptables tidak ditemukan! Pastikan container punya CAP_NET_ADMIN.")
        sys.exit(1)

    # Setup chain SURICATA_BLOCK
    try:
        setup_chain()
    except Exception as e:
        log.critical(f"Gagal setup iptables chain: {e}")
        sys.exit(1)

    # Sync blocked IPs dari state file ke iptables (jika ada dari session sebelumnya)
    if blocked_ips:
        log.info(f"Re-applying {len(blocked_ips)} IP dari state sebelumnya ke iptables...")
        for ip in list(blocked_ips):
            if not is_ip_blocked_in_iptables(ip):
                run_ipt(["-I", IPTABLES_CHAIN, "1", "-s", ip, "-j", "DROP"])
                log.info(f"  Re-blocked: {ip}")

    log.info("Mulai membaca Suricata eve.json...")

    # ─── Main loop: baca event dari eve.json ──────────────────────────────────
    for line in tail_eve_json(EVE_LOG_PATH):
        if not running:
            break

        # Parse JSON
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Hanya proses event tipe "alert"
        if event.get("event_type") != "alert":
            continue

        alert     = event.get("alert", {})
        severity  = alert.get("severity", 99)
        src_ip    = event.get("src_ip", "")
        signature = alert.get("signature", "N/A")
        category  = alert.get("category", "")

        update_dynamic_settings()

        # Filter: skip jika severity rendah, IP kosong, atau whitelisted
        if severity > current_severity or not src_ip or is_whitelisted(src_ip):
            continue

        # Tambah counter
        alert_counts[src_ip] += 1
        count = alert_counts[src_ip]

        log.info(
            f"⚠  [sev={severity}] {src_ip} | "
            f"hit {count}/{current_threshold} | {signature}"
        )

        # Kirim alert ke dashboard
        notify_dashboard({
            "type":      "alert",
            "src_ip":    src_ip,
            "signature": signature,
            "category":  category,
            "severity":  severity,
            "count":     count,
            "threshold": current_threshold,
            "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
        })

        # Blok jika threshold tercapai
        if count >= current_threshold and src_ip not in blocked_ips:
            blocked = block_ip(src_ip, signature, count)
            if blocked:
                save_state()

    log.info("Auto block selesai. Membersihkan...")
    save_state()


if __name__ == "__main__":
    main()
