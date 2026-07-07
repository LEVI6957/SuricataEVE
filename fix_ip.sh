#!/usr/bin/env bash
# =============================================================================
#  fix_ip.sh — Auto Fix IP & Restart saat Jaringan Berubah (WiFi <-> Hotspot)
#  Author  : Levi (github.com/LEVI6957)
#  Usage   : sudo bash fix_ip.sh
#
#  Skrip ini mendeteksi IP Ubuntu Server saat ini, lalu mengupdate
#  semua config yang relevan dan me-restart layanan yang terpengaruh.
#  Jalankan ini setiap kali ganti jaringan (WiFi -> Hotspot atau sebaliknya).
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}";
            echo -e "${BOLD}${BLUE}  $*${NC}";
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}\n"; }

# -- Root Check ----------------------------------------------------------------
[[ $EUID -ne 0 ]] && error "Jalankan dengan sudo: sudo bash fix_ip.sh"

# -- Pindah ke direktori script ------------------------------------------------
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$INSTALL_DIR" || error "Gagal masuk ke direktori $INSTALL_DIR"

header "🔧 SuricataEVE — IP Auto Fix"

# -- Deteksi IP & Interface Saat Ini ------------------------------------------
NEW_IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
[[ -z "$NEW_IFACE" ]] && NEW_IFACE="eth0"

NEW_IP=$(ip -o -4 addr show dev "$NEW_IFACE" | awk '{print $4}' | cut -d/ -f1 | head -n1)
[[ -z "$NEW_IP" ]] && error "Tidak dapat mendeteksi IP! Pastikan interface jaringan aktif."

# Baca IP lama dari .env (jika ada)
OLD_IP=""
if [[ -f ".env" ]]; then
    OLD_IP=$(grep "^SERVER_IP=" .env | cut -d= -f2)
fi

info "Interface  : ${BOLD}${NEW_IFACE}${NC}"
info "IP Lama    : ${BOLD}${OLD_IP:-tidak diketahui}${NC}"
info "IP Baru    : ${BOLD}${CYAN}${NEW_IP}${NC}"

# -- Cek apakah IP berubah ----------------------------------------------------
if [[ "$NEW_IP" == "$OLD_IP" ]]; then
    warn "IP tidak berubah ($NEW_IP). Tidak perlu update."
    echo ""
    info "Jika layanan masih bermasalah, restart paksa dengan: docker compose restart"
    exit 0
fi

echo ""
warn "IP berubah dari ${OLD_IP:-?} -> ${NEW_IP}. Memperbarui semua konfigurasi..."
echo ""

# -- Step 1: Update .env -------------------------------------------------------
header "1. Update .env"
if [[ -f ".env" ]]; then
    sed -i "s/^SERVER_IP=.*/SERVER_IP=${NEW_IP}/" .env
    sed -i "s/^NET_IFACE=.*/NET_IFACE=${NEW_IFACE}/" .env
    info ".env diperbarui (IP: ${NEW_IP}, IFACE: ${NEW_IFACE}) ✓"
else
    warn "File .env tidak ditemukan, membuat baru..."
    cat > .env <<EOF
NET_IFACE=${NEW_IFACE}
SERVER_IP=${NEW_IP}
DASHBOARD_PORT=8080
BLOCK_THRESHOLD=3
ALERT_SEVERITY=2
DASHBOARD_USER=admin
DASHBOARD_PASS=admin123
EOF
    info ".env baru dibuat ✓"
fi

# -- Step 2: Update attack_sim.sh ---------------------------------------------
header "2. Update Script Serangan"
if [[ -f "attack_sim.sh" ]]; then
    sed -i "s/^TARGET_IP=.*/TARGET_IP=\"${NEW_IP}\"/" attack_sim.sh
    info "attack_sim.sh  -> TARGET_IP=\"${NEW_IP}\" ✓"
else
    warn "attack_sim.sh tidak ditemukan, dilewati."
fi

if [[ -f "attack_bab5.sh" ]]; then
    sed -i "s/^TARGET_IP=.*/TARGET_IP=\"${NEW_IP}\"/" attack_bab5.sh
    info "attack_bab5.sh -> TARGET_IP=\"${NEW_IP}\" ✓"
else
    warn "attack_bab5.sh tidak ditemukan, dilewati."
fi

# -- Step 3: Restart Layanan Docker -------------------------------------------
header "3. Restart Layanan"

if ! docker compose ps --quiet 2>/dev/null | grep -q .; then
    warn "Tidak ada container yang berjalan. Menjalankan semua layanan..."
    docker compose up -d
else
    info "Merestart dashboard & auto_block dengan IP baru..."
    docker compose restart dashboard auto_block
fi

# -- Step 4: Verifikasi -------------------------------------------------------
header "4. Verifikasi"

sleep 3

DASH_STATUS=$(docker inspect -f '{{.State.Status}}' suricata_dashboard 2>/dev/null || echo "not found")
BLOCK_STATUS=$(docker inspect -f '{{.State.Status}}' auto_block 2>/dev/null || echo "not found")

if [[ "$DASH_STATUS" == "running" ]]; then
    info "suricata_dashboard : ${GREEN}running ✓${NC}"
else
    warn "suricata_dashboard : ${DASH_STATUS} — cek: docker compose logs dashboard --tail=10"
fi

if [[ "$BLOCK_STATUS" == "running" ]]; then
    info "auto_block         : ${GREEN}running ✓${NC}"
else
    warn "auto_block         : ${BLOCK_STATUS} — cek: docker compose logs auto_block --tail=10"
fi

# -- Ringkasan -----------------------------------------------------------------
header "✅ Selesai!"
echo -e "  IP Server Baru : ${BOLD}${CYAN}${NEW_IP}${NC}"
echo -e "  Interface      : ${BOLD}${NEW_IFACE}${NC}"
echo ""
echo -e "  ${GREEN}[>]${NC} Dashboard  : ${BOLD}http://${NEW_IP}:8080${NC}"
echo -e "  ${GREEN}[>]${NC} EveBox     : ${BOLD}http://${NEW_IP}:5636${NC}"
echo -e "  ${GREEN}[>]${NC} Dummy Web  : ${BOLD}http://${NEW_IP}:80${NC}"
echo ""
warn "Buka URL di atas dari browser Windows untuk akses dashboard."
