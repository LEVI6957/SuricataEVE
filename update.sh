#!/usr/bin/env bash
# =============================================================================
#  update.sh — Update Suricata Auto Block Dashboard
#  Author  : Levi (github.com/LEVI6957)
#  Updates local code from git, rebuilds docker images, and restarts services.
#  Usage: sudo bash update.sh
# =============================================================================
set -uo pipefail

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# Print info messages
function info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

# Print warnings
function warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Auto-generate .env if missing
if [ ! -f ".env" ]; then
    info "File .env tidak ditemukan. Membuat file konfigurasi bawaan..."
    IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n 1)
    if [ -z "$IFACE" ]; then IFACE="eth0"; fi
    
    echo "NET_IFACE=$IFACE" > .env
    echo "SERVER_IP=$(hostname -I | awk '{print $1}')" >> .env
    echo "DASHBOARD_PORT=8080" >> .env
    echo "BLOCK_THRESHOLD=3" >> .env
    echo "ALERT_SEVERITY=2" >> .env
    echo "DASHBOARD_USER=admin" >> .env
    echo "DASHBOARD_PASS=admin123" >> .env
    info "Berhasil mendeteksi antarmuka jaringan: $IFACE"
    warn "⚠️  Ganti DASHBOARD_USER dan DASHBOARD_PASS di file .env sebelum dipakai!"
fi

# Load variables from .env if present
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${BLUE}  $*${NC}"; \
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}\n"; }

# ── Root Check ───────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Run with sudo: sudo bash update.sh"

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$INSTALL_DIR" || error "Gagal masuk ke direktori ${INSTALL_DIR}"

# ══════════════════════════════════════════════════════════════════════════════
header "1. Cek & Persiapkan File"
# ══════════════════════════════════════════════════════════════════════════════
for cname in suricata_main evebox_ui auto_block suricata_dashboard; do
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${cname}$"; then
        docker rm -f "$cname" >/dev/null 2>&1 || true
    fi
done

# Fix permissions on logs directory so EveBox (non-root) can access it
info "Fixing permissions for logs directory..."
mkdir -p logs
touch logs/eve.json
chmod -R 755 logs
chmod 644 logs/eve.json

# Pastikan file-file yang di-mount ada sebagai file (mencegah Docker membuatnya sebagai direktori)
for f in "dashboard/settings.json" "dashboard/whitelist.json" "auto_block/alert_counts.json" "auto_block/blocked_ips.log"; do
    if [[ -d "$f" ]]; then
        rm -rf "$f"
    fi
    if [[ ! -f "$f" ]]; then
        mkdir -p "$(dirname "$f")"
        if [[ "$f" == "dashboard/whitelist.json" ]]; then
            echo "[]" > "$f"
        elif [[ "$f" == "dashboard/settings.json" ]]; then
            echo '{"webhook_url":"","webhook_headers":{},"threshold":3,"severity":2,"interval":10,"secret_token":""}' > "$f"
        elif [[ "$f" == "auto_block/alert_counts.json" ]]; then
            echo "{}" > "$f"
        else
            touch "$f"
        fi
    fi
done

info "Menarik versi terbaru dari Docker Hub (Suricata & Evebox)..."
docker compose pull

info "Rebuilding custom images (dengan cache)..."
docker compose build

info "Restarting services..."
docker compose up -d --remove-orphans

info "Memperbarui daftar ancaman (Rules) Suricata..."

# Tunggu suricata_main siap (maks 30 detik)
for i in $(seq 1 30); do
    if docker exec suricata_main suricata --version >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# ── Update index sumber rules dari internet ───────────────────────────────────
info "Mengambil daftar sumber rules terbaru..."
docker exec suricata_main suricata-update update-sources 2>/dev/null || \
    warn "Gagal update-sources (cek koneksi internet)."

# ── Aktifkan semua sumber rules gratis terbaik ───────────────────────────────
info "Mengaktifkan sumber rules tambahan (gratis)..."

# ET Open — sudah aktif by default, tapi pastikan tetap aktif
docker exec suricata_main suricata-update enable-source et/open 2>/dev/null || true

# Positive Technologies — Deteksi serangan web & exploit tingkat lanjut
docker exec suricata_main suricata-update enable-source ptresearch/attackdetection 2>/dev/null && \
    info "✓ ptresearch/attackdetection diaktifkan" || \
    warn "✗ ptresearch/attackdetection gagal (mungkin butuh registrasi)"

# tgreen/hunting — Rules khusus threat hunting & anomali jaringan
docker exec suricata_main suricata-update enable-source tgreen/hunting 2>/dev/null && \
    info "✓ tgreen/hunting diaktifkan" || \
    warn "✗ tgreen/hunting tidak tersedia"

# abuse.ch SSLBL — Blacklist SSL fingerprint malware & botnet
docker exec suricata_main suricata-update enable-source sslbl/ssl-fp-blacklist 2>/dev/null && \
    info "✓ sslbl/ssl-fp-blacklist diaktifkan" || \
    warn "✗ sslbl tidak tersedia"

# abuse.ch Botnet C2 — IP botnet & C2 server terkenal per port
docker exec suricata_main suricata-update enable-source abuse.ch/botcc.port-grouped 2>/dev/null && \
    info "✓ abuse.ch/botcc diaktifkan" || \
    warn "✗ abuse.ch/botcc tidak tersedia"

# OISF Traffic ID — Deteksi protokol & traffic fingerprinting
docker exec suricata_main suricata-update enable-source oisf/trafficid 2>/dev/null && \
    info "✓ oisf/trafficid diaktifkan" || \
    warn "✗ oisf/trafficid tidak tersedia"

# ── Jalankan update gabungan semua sumber ─────────────────────────────────────
info "Menggabungkan semua rules dari semua sumber..."
docker exec suricata_main suricata-update || warn "Gagal update rules Suricata."

# Reload rules tanpa restart kontainer
docker exec suricata_main kill -USR2 1 2>/dev/null || true
info "Rules berhasil di-reload!"

# Tampilkan jumlah rules yang aktif
RULE_COUNT=$(docker exec suricata_main suricata-update --no-merge 2>/dev/null | grep -oP '\d+ rules' | tail -1 || echo "?")
info "Total rules aktif: ${BOLD}${RULE_COUNT:-cek manual dengan: docker exec suricata_main suricata-update}${NC}"


# ══════════════════════════════════════════════════════════════════════════════
header "3. Cleanup"
# ══════════════════════════════════════════════════════════════════════════════

info "Cleaning up unused docker images (dangling)..."
docker image prune -f

echo ""
header "✅ Update Complete!"
echo -e "  🛡️  ${BOLD}Dashboard${NC}  : ${CYAN}http://$(hostname -I | awk '{print $1}'):${DASHBOARD_PORT:-8080}${NC}"
echo -e "  📊  ${BOLD}EveBox${NC}     : ${CYAN}http://$(hostname -I | awk '{print $1}'):5636${NC}"
echo ""
