#!/usr/bin/env bash
# =============================================================================
#  reset_system.sh — Membersihkan semua log dan blokir SuricataEVE
#  Author: Levi (github.com/LEVI6957)
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR]${NC} Script ini harus dijalankan dengan akses root/sudo!"
   exit 1
fi

echo -e "${GREEN}[*]${NC} Mengosongkan Aturan Firewall (IPTables SURICATA_BLOCK)..."
# Flush chain IPv4
iptables -F SURICATA_BLOCK 2>/dev/null
# Flush chain IPv6 (opsional, jika ada)
ip6tables -F SURICATA_BLOCK 2>/dev/null

echo -e "${GREEN}[*]${NC} Menghapus Log Suricata (eve.json)..."
> ./logs/eve.json

echo -e "${GREEN}[*]${NC} Menghapus Log Pemblokiran (blocked_ips.log)..."
> ./auto_block/blocked_ips.log

echo -e "${GREEN}[*]${NC} Mereset Memori Skrip (alert_counts.json)..."
echo '{"alert_counts": {}, "blocked_ips": []}' > ./auto_block/alert_counts.json

echo -e "${GREEN}[*]${NC} Menghapus Database EveBox (Histori Web UI)..."
# Menghapus database SQLite EveBox di dalam container
docker exec evebox_ui rm -f /var/lib/evebox/events.sqlite 2>/dev/null || true

echo -e "${GREEN}[*]${NC} Merestart Sistem (Docker Containers)..."
# Restart agar auto_block.py, dashboard, dan evebox membaca file log & db yang kosong (fresh)
docker compose restart

echo ""
echo -e "${GREEN}[+] SELESAI!${NC} Sistem SuricataEVE telah di-reset seperti baru!"
echo "Dashboard sekarang kosong, IPTables bersih, dan siap untuk pengujian BAB V."
