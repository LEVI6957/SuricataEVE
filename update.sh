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
    info "Berhasil mendeteksi antarmuka jaringan: $IFACE"
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
            echo '{"webhook_url":"","threshold":3,"severity":2,"interval":10}' > "$f"
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
docker exec suricata_main suricata-update || warn "Gagal update rules Suricata (mungkin belum siap)."
docker exec suricata_main kill -USR2 1 || true # Reload rules tanpa matiin kontainer

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
