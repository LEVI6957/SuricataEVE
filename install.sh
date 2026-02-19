#!/usr/bin/env bash
# =============================================================================
#  install.sh — Suricata Auto Block Dashboard
#  1x jalankan di Ubuntu Server, semua langsung beres.
#  Usage: sudo bash install.sh
# =============================================================================
set -euo pipefail

# ── Warna ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${BLUE}  $*${NC}"; \
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}\n"; }

# ── Cek root ─────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Jalankan dengan sudo: sudo bash install.sh"

# ── Banner ───────────────────────────────────────────────────────────────────
clear
echo -e "${BOLD}${BLUE}"
cat << 'EOF'
  ____                  _           _          ___ ____  ____
 / ___| _   _ _ __ _ _(_) ___ __ _| |_ __ _  |_ _|  _ \/ ___|
 \___ \| | | | '__| |_| |/ __/ _` | __/ _` |  | || | | \___ \
  ___) | |_| | |  | | | | (_| (_| | || (_| |  | || |_| |___) |
 |____/ \__,_|_|  |_| |_|\___\__,_|\__\__,_| |___|____/|____/
                  Auto Block Dashboard — Ubuntu Server Installer
EOF
echo -e "${NC}"

# ══════════════════════════════════════════════════════════════════════════════
header "1. Konfigurasi"
# ══════════════════════════════════════════════════════════════════════════════

# Deteksi IP server secara otomatis
DEFAULT_IP=$(hostname -I | awk '{print $1}')
DEFAULT_PORT="8080"
DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)

echo -e "${BOLD}Deteksi otomatis:${NC}"
echo -e "  IP Server    : ${GREEN}${DEFAULT_IP}${NC}"
echo -e "  Interface    : ${GREEN}${DEFAULT_IFACE}${NC}"
echo ""

read -rp "$(echo -e "${BOLD}IP server untuk dashboard${NC} [${DEFAULT_IP}]: ")" SERVER_IP
SERVER_IP="${SERVER_IP:-$DEFAULT_IP}"

read -rp "$(echo -e "${BOLD}Port dashboard${NC} [${DEFAULT_PORT}]: ")" DASHBOARD_PORT
DASHBOARD_PORT="${DASHBOARD_PORT:-$DEFAULT_PORT}"

read -rp "$(echo -e "${BOLD}Network interface Suricata${NC} [${DEFAULT_IFACE}]: ")" NET_IFACE
NET_IFACE="${NET_IFACE:-$DEFAULT_IFACE}"

read -rp "$(echo -e "${BOLD}Webhook URL (Telegram/Discord/Slack, kosongkan=skip)${NC}: ")" WEBHOOK_URL
WEBHOOK_URL="${WEBHOOK_URL:-}"

read -rp "$(echo -e "${BOLD}Block threshold (jumlah alert sebelum blok)${NC} [3]: ")" BLOCK_THRESHOLD
BLOCK_THRESHOLD="${BLOCK_THRESHOLD:-3}"

read -rp "$(echo -e "${BOLD}Min severity (1=High 2=Medium 3=Low)${NC} [2]: ")" ALERT_SEVERITY
ALERT_SEVERITY="${ALERT_SEVERITY:-2}"

echo ""
echo -e "${BOLD}Ringkasan konfigurasi:${NC}"
echo -e "  Dashboard    : http://${SERVER_IP}:${DASHBOARD_PORT}"
echo -e "  Interface    : ${NET_IFACE}"
echo -e "  Threshold    : ${BLOCK_THRESHOLD} alerts"
echo -e "  Severity     : ${ALERT_SEVERITY}"
echo -e "  Webhook      : ${WEBHOOK_URL:-tidak dikonfigurasi}"
echo ""
read -rp "$(echo -e "${BOLD}Lanjutkan? [Y/n]: ${NC}")" CONFIRM
[[ "${CONFIRM,,}" == "n" ]] && echo "Dibatalkan." && exit 0

# ══════════════════════════════════════════════════════════════════════════════
header "2. Install Dependencies"
# ══════════════════════════════════════════════════════════════════════════════

info "Update apt..."
apt-get update -qq

# Docker
if ! command -v docker &>/dev/null; then
    info "Menginstall Docker..."
    apt-get install -y -qq ca-certificates curl gnupg lsb-release
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
    success "Docker terinstall"
else
    success "Docker sudah ada ($(docker --version | cut -d' ' -f3 | tr -d ','))"
fi

# Docker Compose
if ! docker compose version &>/dev/null; then
    info "Menginstall Docker Compose plugin..."
    apt-get install -y -qq docker-compose-plugin
fi
success "Docker Compose siap"

# UFW
if ! command -v ufw &>/dev/null; then
    info "Menginstall UFW..."
    apt-get install -y -qq ufw
fi
success "UFW siap"

# Git
if ! command -v git &>/dev/null; then
    apt-get install -y -qq git
fi

# ══════════════════════════════════════════════════════════════════════════════
header "3. Setup Project"
# ══════════════════════════════════════════════════════════════════════════════

INSTALL_DIR="/opt/suricata-dashboard"

if [[ -d "$INSTALL_DIR" ]]; then
    warn "Direktori ${INSTALL_DIR} sudah ada."
    read -rp "$(echo -e "${BOLD}Update dari git? [Y/n]: ${NC}")" DO_PULL
    if [[ "${DO_PULL,,}" != "n" ]]; then
        cd "$INSTALL_DIR"
        git fetch origin
        git reset --hard origin/main
        success "Repository diupdate"
    fi
else
    info "Menyalin project ke ${INSTALL_DIR}..."
    # Jika script dijalankan dari dalam repo
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "${SCRIPT_DIR}/docker-compose.yml" ]]; then
        cp -r "$SCRIPT_DIR" "$INSTALL_DIR"
        success "Project disalin ke ${INSTALL_DIR}"
    else
        error "docker-compose.yml tidak ditemukan di ${SCRIPT_DIR}. Taruh install.sh di root project."
    fi
fi

cd "$INSTALL_DIR"

# Buat folder logs dan file-file yang dibutuhkan oleh volume mount
mkdir -p logs
touch logs/eve.json                   # EveBox butuh folder ini ada
touch auto_block/blocked_ips.log      # Dashboard & auto_block baca file ini
echo '{}' > auto_block/alert_counts.json  # State persistensi counter IP
if [[ ! -f dashboard/settings.json ]]; then
    touch dashboard/settings.json
fi

# Inisialisasi settings.json
cat > dashboard/settings.json << SETTINGS
{
  "webhook_url": "${WEBHOOK_URL}",
  "webhook_headers": {},
  "threshold": ${BLOCK_THRESHOLD},
  "severity": ${ALERT_SEVERITY},
  "interval": 10,
  "secret_token": ""
}
SETTINGS
success "File runtime dibuat (eve.json, blocked_ips.log, alert_counts.json, settings.json)"

# ══════════════════════════════════════════════════════════════════════════════
header "4. Konfigurasi .env & docker-compose"
# ══════════════════════════════════════════════════════════════════════════════

cat > .env << ENV
SERVER_IP=${SERVER_IP}
DASHBOARD_PORT=${DASHBOARD_PORT}
NET_IFACE=${NET_IFACE}
BLOCK_THRESHOLD=${BLOCK_THRESHOLD}
ALERT_SEVERITY=${ALERT_SEVERITY}
CHECK_INTERVAL=10
WEBHOOK_URL=${WEBHOOK_URL}
ENV
success ".env dibuat"

# Update interface jaringan di docker-compose.yml
sed -i "s|command: -i .*|command: -i ${NET_IFACE}|" docker-compose.yml
success "Interface '${NET_IFACE}' dikonfigurasi di docker-compose.yml"

# ══════════════════════════════════════════════════════════════════════════════
header "5. Konfigurasi UFW Firewall"
# ══════════════════════════════════════════════════════════════════════════════

info "Mengaktifkan UFW..."
ufw --force enable

# Izinkan SSH agar tidak terkunci
ufw allow OpenSSH
ufw allow "${DASHBOARD_PORT}/tcp" comment "Suricata Dashboard"
ufw allow "5636/tcp"              comment "EveBox UI"

success "UFW dikonfigurasi (SSH + Dashboard + EveBox diizinkan)"

# ══════════════════════════════════════════════════════════════════════════════
header "6. Build & Jalankan Docker"
# ══════════════════════════════════════════════════════════════════════════════

info "Build docker images..."
docker compose build --no-cache

info "Menjalankan semua service..."
docker compose up -d

# Tunggu sebentar lalu cek status
sleep 5

echo ""
echo -e "${BOLD}Status container:${NC}"
docker compose ps

# ══════════════════════════════════════════════════════════════════════════════
header "7. Setup Systemd (Auto-start saat reboot)"
# ══════════════════════════════════════════════════════════════════════════════

cat > /etc/systemd/system/suricata-dashboard.service << SERVICE
[Unit]
Description=Suricata Auto Block Dashboard
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable suricata-dashboard.service
success "Service systemd dikonfigurasi (auto-start aktif)"

# ══════════════════════════════════════════════════════════════════════════════
header "✅ Instalasi Selesai!"
# ══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}${GREEN}Semua service berjalan!${NC}\n"
echo -e "  🛡️  ${BOLD}Dashboard${NC}  : ${CYAN}http://${SERVER_IP}:${DASHBOARD_PORT}${NC}"
echo -e "  📊  ${BOLD}EveBox${NC}     : ${CYAN}http://${SERVER_IP}:5636${NC}"
echo -e "  📁  ${BOLD}Direktori${NC}  : ${INSTALL_DIR}"
echo -e "  📄  ${BOLD}Log IP blok${NC}: ${INSTALL_DIR}/auto_block/blocked_ips.log"
echo ""
echo -e "${BOLD}Perintah berguna:${NC}"
echo -e "  docker compose -f ${INSTALL_DIR}/docker-compose.yml logs -f    # Live logs"
echo -e "  docker compose -f ${INSTALL_DIR}/docker-compose.yml ps         # Status"
echo -e "  docker compose -f ${INSTALL_DIR}/docker-compose.yml restart    # Restart"
echo -e "  systemctl stop suricata-dashboard                              # Stop semua"
echo ""
