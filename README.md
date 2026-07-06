# 🛡️ Suricata Auto Block Dashboard

Sistem deteksi & pemblokiran otomatis berbasis **Suricata IDS**, dilengkapi web dashboard real-time.  
Setiap IP penyerang yang memicu alert melebihi threshold akan **otomatis diblokir via iptables**.

>  Proyek ini dibuat sebagai implementasi nyata sistem keamanan jaringan berbasis open-source untuk keperluan penelitian.

---

## Stack Teknologi

| Service | Fungsi |
|---|---|
| **Suricata 8.x** | Network IDS — sniff traffic & tulis alert ke `eve.json` |
| **EveBox** | UI viewer alert Suricata (analisis detail log) |
| **auto_block** | Baca `eve.json` real-time, blok IP via **iptables** otomatis |
| **dashboard** | Web UI: live feed alert, manage blocked IPs, webhook notifikasi |

> Semua service berjalan via **Docker** — tidak perlu install Suricata secara manual.

---

## Cara Kerja

```
Suricata sniff traffic (eth0 + lo)
       ↓
   eve.json (log alert real-time)
       ↓
auto_block.py baca real-time
       ↓
IP mencapai threshold? → iptables -I SURICATA_BLOCK -s <IP> -j DROP
       ↓
Notifikasi ke Dashboard (WebSocket) + Webhook (Discord/Slack/Telegram)
```

**iptables custom chain** `SURICATA_BLOCK` digunakan — terpisah dari rule firewall lain, mudah di-audit dan di-reset.

---

## Instalasi (Ubuntu Server)

### Prasyarat
- Ubuntu 20.04 / 22.04 / 24.04
- Docker & Docker Compose Plugin

```bash
# 1. Install Docker (jika belum ada)
sudo apt update && sudo apt install -y docker.io docker-compose-plugin

# 2. Clone repo
git clone https://github.com/LEVI6957/SuricataEVE.git
cd SuricataEVE

# 3. Jalankan script instalasi otomatis
sudo bash update.sh
```

Script `update.sh` akan otomatis:
- Mendeteksi network interface
- Membuat file `.env`
- Mengaktifkan semua sumber rules Suricata (ET Open + ptresearch + abuse.ch + tgreen + oisf)
- Membangun dan menjalankan semua Docker container

---

## Konfigurasi

Edit file `.env` setelah instalasi:

```env
SERVER_IP=0.0.0.0          # IP server (0.0.0.0 = semua interface)
DASHBOARD_PORT=8080        # Port dashboard
NET_IFACE=eth0             # Network interface yang di-sniff Suricata (cek: ip a)
BLOCK_THRESHOLD=3          # Jumlah alert sebelum IP diblok
ALERT_SEVERITY=2           # 1=High only, 2=Medium+High, 3=Semua alert
DASHBOARD_USER=admin       # Username login dashboard
DASHBOARD_PASS=admin123    # Password login dashboard (WAJIB diganti!)
```

> **Cara cek network interface:** jalankan `ip a` di server, cari nama interface aktif (contoh: `eth0`, `ens33`, `enp3s0`)

---

## Akses Dashboard

| URL | Keterangan |
|---|---|
| `http://x.x.x.x:8080` | Dashboard utama (live feed + firewall control) |
| `http://x.x.x.x:5636` | EveBox (analisis alert detail) |

---

## Fitur Dashboard

- 📡 **Live Feed** — alert Suricata tampil real-time via WebSocket
- 🔒 **IP Diblok** — daftar IP yang diblok + tombol Unblock
- 🛡️ **IP Whitelist** — daftar IP yang dikecualikan dari pemblokiran
- 🔔 **Webhook Notifikasi** — kirim notifikasi ke Discord, Slack, atau Telegram otomatis
- ⚙️ **Konfigurasi** — ubah threshold & severity langsung dari UI tanpa restart
- 🚫 **Brute Force Guard** — login gagal 5x → IP penyerang otomatis diblokir
- 📊 **Stats** — total alert, total blocked, jumlah whitelist, uptime

---

## Sumber Rules Suricata

Sistem secara otomatis mengaktifkan rule database berikut (±40.000+ rules):

| Sumber | Spesialisasi |
|---|---|
| **ET Open** | 28.500+ rules umum (default) |
| **ptresearch/attackdetection** | Serangan web, exploit, APT |
| **tgreen/hunting** | Threat hunting & anomali jaringan |
| **sslbl/ssl-fp-blacklist** | SSL/TLS malware & botnet fingerprint |
| **abuse.ch/botcc** | IP botnet & server C2 aktif |
| **oisf/trafficid** | Deteksi protokol jaringan |

---

## Webhook Discord / Slack / Telegram

Konfigurasi langsung dari panel **Webhook Notifikasi** di dashboard — **tidak perlu restart**.

Event yang memicu notifikasi:
- `BLOCKED` — IP baru diblokir
- `HIGH_ALERT` — Alert severity tinggi terdeteksi
- `BRUTE FORCE` — Percobaan login paksa ke dashboard
- `UNBLOCKED` — IP dibebaskan secara manual
- `LOGIN` — Admin berhasil login
- `WHITELIST_ADD/REMOVE` — Perubahan whitelist

---

## Simulasi Serangan (untuk Pengujian)

Dari mesin penyerang, jalankan:

```bash
# Download script simulasi
curl -o ~/attack_sim.sh https://raw.githubusercontent.com/LEVI6957/SuricataEVE/main/attack_sim.sh

# Jalankan simulasi 20 IP penyerang berbeda dengan payload Log4Shell
sudo bash ~/attack_sim.sh <IP_SERVER> 80
```

---

## Perintah Berguna

```bash
# Cek status semua service
docker compose ps

# Lihat log Suricata
docker compose logs -f suricata

# Lihat log dashboard
docker compose logs -f dashboard

# Cek IP yang diblokir iptables
sudo iptables -n -L SURICATA_BLOCK --line-numbers

# Update sistem & rules
sudo bash update.sh

# Hapus semua (uninstall)
sudo bash uninstall.sh
```

---

## Lisensi

MIT License — lihat file [LICENSE](LICENSE)

---

## Author

**Levi** — [@LEVI6957](https://github.com/LEVI6957)  
Dikembangkan sebagai proyek sistem keamanan jaringan berbasis open-source.
