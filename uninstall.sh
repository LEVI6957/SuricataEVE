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
echo -e "   • UFW rules untuk port 8080 & 5636"
echo -e "   • Systemd service suricata-dashboard"
echo -e "   • Folder instalasi: ${INSTALL_DIR}"
echo ""
read -rp "$(echo -e "${BOLD}Yakin ingin uninstall semua? [y/N]: ${NC}")" CONFIRM
[[ "${CONFIRM,,}" != "y" ]] && echo "Dibatalkan." && exit 0

# ══════════════════════════════════════════════════════════════════════════════
header "1. Stop & Hapus Container"
# ══════════════════════════════════════════════════════════════════════════════

COMPOSE_FILE="${INSTALL_DIR}/docker-compose.yml"

if [[ -f "$COMPOSE_FILE" ]]; then
    info "Menghentikan semua service..."
    docker compose -f "$COMPOSE_FILE" down --remove-orphans --timeout 10 2>/dev/null || true
    success "Container dihentikan"
else
    warn "docker-compose.yml tidak ditemukan di ${INSTALL_DIR}, mencoba hapus container langsung..."
fi

# Hapus container by name jika masih ada
CONTAINERS=(suricata_main evebox_ui auto_block suricata_dashboard)
for cname in "${CONTAINERS[@]}"; do
    if docker ps -a --format '{{.Names}}' | grep -q "^${cname}$"; then
        docker rm -f "$cname" 2>/dev/null && success "Container '${cname}' dihapus"
    fi
done

# ══════════════════════════════════════════════════════════════════════════════
header "2. Hapus Docker Images"
# ══════════════════════════════════════════════════════════════════════════════

IMAGES=(
    "jasonish/suricata:latest"
    "jasonish/evebox:latest"
    "suricataeve-dashboard"
    "suricataeve-auto_block"
    "library/suricataeve-dashboard"
    "library/suricataeve-auto_block"
)

for img in "${IMAGES[@]}"; do
    if docker image inspect "$img" &>/dev/null; then
        docker rmi -f "$img" 2>/dev/null && success "Image '${img}' dihapus"
    fi
done

# Hapus dangling images
docker image prune -f &>/dev/null
success "Dangling images dibersihkan"

# ══════════════════════════════════════════════════════════════════════════════
header "3. Hapus Docker Volumes"
# ══════════════════════════════════════════════════════════════════════════════

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

# Hapus semua volume orphan dari project ini
docker volume prune -f --filter "label=com.docker.compose.project=suricata-dashboard" &>/dev/null || true
docker volume prune -f --filter "label=com.docker.compose.project=suricataeve" &>/dev/null || true

# ══════════════════════════════════════════════════════════════════════════════
header "4. Hapus UFW Rules"
# ══════════════════════════════════════════════════════════════════════════════

if command -v ufw &>/dev/null; then
    # Baca port dari .env jika ada
    ENV_FILE="${INSTALL_DIR}/.env"
    DASH_PORT="8080"
    if [[ -f "$ENV_FILE" ]]; then
        DASH_PORT=$(grep -E '^DASHBOARD_PORT=' "$ENV_FILE" | cut -d= -f2 | tr -d '[:space:]') || DASH_PORT="8080"
    fi

    info "Menghapus UFW rule port ${DASH_PORT} dan 5636..."
    ufw delete allow "${DASH_PORT}/tcp" 2>/dev/null || true
    ufw delete allow "5636/tcp"         2>/dev/null || true
    success "UFW rules dihapus"
else
    warn "UFW tidak ditemukan, skip"
fi

# ══════════════════════════════════════════════════════════════════════════════
header "5. Hapus Systemd Service"
# ══════════════════════════════════════════════════════════════════════════════

SERVICE_FILE="/etc/systemd/system/suricata-dashboard.service"

if [[ -f "$SERVICE_FILE" ]]; then
    systemctl stop  suricata-dashboard 2>/dev/null || true
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
echo -e "  • SSH rule di UFW — tetap aman"
echo ""
echo -e "${CYAN}Untuk uninstall Docker juga:${NC}"
echo -e "  apt-get purge docker-ce docker-ce-cli containerd.io docker-compose-plugin -y"
echo -e "  rm -rf /var/lib/docker /etc/docker"
echo ""
