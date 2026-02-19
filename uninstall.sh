#!/usr/bin/env bash
# =============================================================================
#  uninstall.sh — Suricata Auto Block Dashboard
#  Hapus semua container, volume, image, rules UFW, service systemd, & folder.
#  Usage: sudo bash uninstall.sh
# =============================================================================
set -uo pipefail

# ── Warna ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${BLUE}  $*${NC}"; \
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}\n"; }

# ── Cek root ─────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && echo -e "${RED}[ERROR]${NC} Jalankan dengan sudo: sudo bash uninstall.sh" && exit 1

INSTALL_DIR="/opt/suricata-dashboard"
COMPOSE_FILE="${INSTALL_DIR}/docker-compose.yml"

# ── Banner ───────────────────────────────────────────────────────────────────
clear
echo -e "${BOLD}${RED}"
cat << 'EOF'
  _   _       _           _        _ _
 | | | |_ __ (_)_ __  ___| |_ __ _| | |
 | | | | '_ \| | '_ \/ __| __/ _` | | |
 | |_| | | | | | | | \__ \ || (_| | | |
  \___/|_| |_|_|_| |_|___/\__\__,_|_|_|
          Suricata Dashboard — Uninstaller
EOF
echo -e "${NC}"

echo -e "${BOLD}${RED}⚠  PERINGATAN:${NC} Script ini akan menghapus:"
echo -e "   • Semua container Suricata Dashboard"
echo -e "   • Docker images yang dibangun (dashboard & auto_block)"
echo -e "   • Docker volumes (evebox-data, suricata-rules, suricata-config)"
echo -e "   • UFW rules untuk dashboard port & 5636"
echo -e "   • Systemd service suricata-dashboard"
echo -e "   • Folder instalasi: ${INSTALL_DIR}"
echo ""
read -rp "$(echo -e "${BOLD}Yakin ingin uninstall semua? [y/N]: ${NC}")" CONFIRM
[[ "${CONFIRM,,}" != "y" ]] && echo "Dibatalkan." && exit 0

# ══════════════════════════════════════════════════════════════════════════════
# BACA .env DULU sebelum folder dihapus
# ══════════════════════════════════════════════════════════════════════════════
DASH_PORT="8080"
ENV_FILE="${INSTALL_DIR}/.env"
if [[ -f "$ENV_FILE" ]]; then
    _port=$(grep -E '^DASHBOARD_PORT=' "$ENV_FILE" | cut -d= -f2 | tr -d '[:space:]')
    [[ -n "$_port" ]] && DASH_PORT="$_port"
    info "Port dashboard dari .env: ${DASH_PORT}"
fi

# ══════════════════════════════════════════════════════════════════════════════
header "1. Stop & Hapus Container, Volume, dan Images"
# ══════════════════════════════════════════════════════════════════════════════

if [[ -f "$COMPOSE_FILE" ]]; then
    info "Menghentikan service dan menghapus volumes + images via docker compose..."
    # --volumes   : hapus volume yang didefinisikan di compose
    # --rmi local : hapus images yang di-build lokal (dashboard & auto_block)
    # --remove-orphans : hapus container yang tidak ada di compose
    docker compose -f "$COMPOSE_FILE" down \
        --volumes \
        --rmi local \
        --remove-orphans \
        --timeout 15 2>/dev/null || true
    success "Container, volume compose, dan local images dihapus"
else
    warn "docker-compose.yml tidak ditemukan di ${INSTALL_DIR}, hapus container/volume manual..."
fi

# Hapus container by name jika masih ada (safety net)
info "Memastikan tidak ada container tersisa..."
for cname in suricata_main evebox_ui auto_block suricata_dashboard; do
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${cname}$"; then
        docker rm -f "$cname" 2>/dev/null && success "Container '${cname}' dihapus"
    fi
done

# ══════════════════════════════════════════════════════════════════════════════
header "2. Hapus Docker Images (safety net)"
# ══════════════════════════════════════════════════════════════════════════════

# Cakup berbagai kemungkinan nama image berdasarkan project dir name
# Project dir /opt/suricata-dashboard → nama image: suricata-dashboard-<service>
# Project dir ~/SuricataEVE           → nama image: suricataeve-<service>
IMAGES=(
    "jasonish/suricata:latest"
    "jasonish/evebox:latest"
    "suricata-dashboard-dashboard"
    "suricata-dashboard-auto_block"
    "suricataeve-dashboard"
    "suricataeve-auto_block"
)

for img in "${IMAGES[@]}"; do
    if docker image inspect "$img" &>/dev/null; then
        docker rmi -f "$img" 2>/dev/null && success "Image '${img}' dihapus"
    fi
done

# Hapus dangling images saja (bukan semua unused — jangan hapus image user lain)
docker image prune -f &>/dev/null && success "Dangling images dibersihkan"

# ══════════════════════════════════════════════════════════════════════════════
header "3. Hapus Docker Volumes (safety net)"
# ══════════════════════════════════════════════════════════════════════════════

# Cakup semua kemungkinan nama volume (prefix dari project dir name)
VOLUMES=(
    "suricata-dashboard_evebox-data"
    "suricata-dashboard_suricata-rules"
    "suricata-dashboard_suricata-config"
    "suricataeve_evebox-data"
    "suricataeve_suricata-rules"
    "suricataeve_suricata-config"
)

for vol in "${VOLUMES[@]}"; do
    if docker volume inspect "$vol" &>/dev/null; then
        docker volume rm "$vol" 2>/dev/null && success "Volume '${vol}' dihapus"
    fi
done

# ══════════════════════════════════════════════════════════════════════════════
header "4. Hapus UFW Rules"
# ══════════════════════════════════════════════════════════════════════════════

if command -v ufw &>/dev/null; then
    info "Menghapus UFW rule port ${DASH_PORT}/tcp dan 5636/tcp..."
    ufw delete allow "${DASH_PORT}/tcp" 2>/dev/null && success "UFW rule port ${DASH_PORT} dihapus" || warn "Rule port ${DASH_PORT} tidak ditemukan"
    ufw delete allow "5636/tcp"         2>/dev/null && success "UFW rule port 5636 dihapus"         || warn "Rule port 5636 tidak ditemukan"
    # Catatan: rule OpenSSH ditambahkan oleh install.sh TIDAK dihapus di sini
    # agar koneksi SSH tidak terputus
else
    warn "UFW tidak ditemukan, skip"
fi

# ══════════════════════════════════════════════════════════════════════════════
header "5. Hapus Systemd Service"
# ══════════════════════════════════════════════════════════════════════════════

SERVICE_FILE="/etc/systemd/system/suricata-dashboard.service"

if [[ -f "$SERVICE_FILE" ]]; then
    systemctl stop    suricata-dashboard 2>/dev/null || true
    systemctl disable suricata-dashboard 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    success "Systemd service dihapus"
else
    warn "Systemd service tidak ditemukan, skip"
fi

# ══════════════════════════════════════════════════════════════════════════════
header "6. Hapus Folder Instalasi"
# ══════════════════════════════════════════════════════════════════════════════

if [[ -d "$INSTALL_DIR" ]]; then
    info "Menghapus ${INSTALL_DIR}..."
    rm -rf "$INSTALL_DIR"
    success "Folder ${INSTALL_DIR} dihapus"
else
    warn "Folder ${INSTALL_DIR} tidak ditemukan, skip"
fi

# ══════════════════════════════════════════════════════════════════════════════
header "✅ Uninstall Selesai!"
# ══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}${GREEN}Semua komponen Suricata Dashboard telah dihapus.${NC}\n"
echo -e "Yang masih tersisa (tidak dihapus otomatis):"
echo -e "  • Docker engine itu sendiri"
echo -e "  • UFW (firewall) — masih aktif"
echo -e "  • UFW rule SSH (OpenSSH) — sengaja tidak dihapus agar SSH tidak putus"
echo ""
echo -e "${CYAN}Untuk uninstall Docker juga (opsional):${NC}"
echo -e "  apt-get purge -y docker-ce docker-ce-cli containerd.io docker-compose-plugin"
echo -e "  rm -rf /var/lib/docker /etc/docker"
echo ""
