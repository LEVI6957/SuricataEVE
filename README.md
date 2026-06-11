# 🛡️ Suricata Auto Block Dashboard

Sistem deteksi & pemblokiran otomatis berbasis **Suricata IDS**, dilengkapi web dashboard real-time.  
Setiap IP penyerang yang memicu alert melebihi threshold akan **otomatis diblokir via iptables**.

---

## Stack

| Service | Fungsi |
|---|---|
| **Suricata** | Network IDS — sniff traffic & tulis alert ke `eve.json` |
| **EveBox** | UI viewer alert Suricata (analisis detail) |
| **auto_block** | Baca `eve.json` real-time, blok IP via **iptables** otomatis |
| **dashboard** | Web UI: live feed alert, manage blocked IPs, webhook notifikasi |

> Semua service berjalan via **Docker** — tidak perlu install Suricata secara manual.

---

## Cara Kerja

```
Suricata sniff traffic
       ↓
   eve.json (log alert)
       ↓
auto_block.py membaca real-time
       ↓
IP mencapai threshold? → iptables -I SURICATA_BLOCK -s <IP> -j DROP
       ↓
Notifikasi ke dashboard (WebSocket) + webhook (Discord/Slack/Telegram)
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

# 3. Konfigurasi environment
cp .env.example .env
nano .env   # sesuaikan NET_IFACE dan SERVER_IP

# 4. Jalankan semua service
sudo docker compose up -d
```

---

## Konfigurasi

Edit file `.env`:

```env
SERVER_IP=192.168.1.5      # IP server kamu (untuk binding dashboard)
DASHBOARD_PORT=8080        # Port dashboard
NET_IFACE=eth0             # Network interface yang di-sniff Suricata (cek: ip a)
BLOCK_THRESHOLD=3          # Jumlah alert sebelum IP diblok
ALERT_SEVERITY=2           # 1=High only, 2=Medium+High, 3=Semua alert
```

> **Cara cek network interface:** jalankan `ip a` di server, cari nama interface aktif (contoh: `eth0`, `ens33`, `enp3s0`)

---

## Akses Dashboard

| URL | Keterangan |
|---|---|
| `http://SERVER_IP:8080` | Dashboard utama (live feed + firewall control) |
| `http://SERVER_IP:5636` | EveBox (analisis alert detail) |

---

## Fitur Dashboard

- 📡 **Live Feed** — alert Suricata tampil real-time via WebSocket
- 🔒 **Blocked IPs** — daftar IP yang diblok + tombol Unblock
- 🔔 **Webhook Notifikasi** — kirim notifikasi ke Discord, Slack, atau Telegram otomatis
- ⚙️ **Konfigurasi** — ubah threshold & severity langsung dari UI tanpa restart
- 📊 **Stats** — total alert, total blocked, top attacker, uptime

---

## Webhook Discord / Slack / Telegram

Konfigurasi langsung dari panel **Webhook Notifikasi** di dashboard — **tidak perlu restart**.

| Platform | Format URL | Keterangan |
|---|---|---|
| **Discord** | `https://discord.com/api/webhooks/...` | Auto-format embed dengan warna & field |
| **Slack** | `https://hooks.slack.com/services/...` | Format teks Slack |
| **Telegram** | `https://api.telegram.org/bot<TOKEN>/sendMessage` | JSON generic |
| **Custom** | URL apapun | JSON generic dikirim |

---

## Perintah Berguna

```bash
# Status semua service
sudo docker compose ps

# Monitor log auto-block (lihat IP yang diblok real-time)
sudo docker compose logs -f auto_block

# Monitor log dashboard
sudo docker compose logs -f dashboard

# Cek rule iptables aktif (IP yang diblok)
sudo iptables -n -L SURICATA_BLOCK

# Update ke versi terbaru
git pull origin main
sudo docker compose down
sudo docker compose build
sudo docker compose up -d

# Restart semua service
sudo docker compose restart

# Stop semua service
sudo docker compose down
```

---

## Struktur Project

```
SuricataEVE/
├── docker-compose.yml              # Orkestrasi semua service
├── install.sh                      # Script instalasi otomatis
├── .env.example                    # Template konfigurasi
├── auto_block/
│   ├── auto_block.py               # Engine: baca eve.json → blok via iptables
│   └── Dockerfile
├── dashboard/
│   ├── app.py                      # FastAPI: REST API + WebSocket + Webhook
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── settings.json               # Penyimpanan webhook URL & konfigurasi
│   └── static/
│       └── index.html              # UI dark theme (glassmorphism)
└── logs/                           # eve.json dari Suricata (auto-generated)
```

---

## Troubleshooting

**Suricata tidak sniff traffic?**
```bash
# Pastikan NET_IFACE di .env benar
ip a
sudo docker compose logs suricata
```

**IP tidak terblok?**
```bash
# Pastikan container punya privilege iptables
sudo docker compose logs auto_block
sudo iptables -n -L SURICATA_BLOCK
```

**Webhook Discord tidak terkirim?**
```bash
# Cek log dashboard
sudo docker compose logs dashboard
# Pastikan URL format: https://discord.com/api/webhooks/ID/TOKEN
```

**Dashboard tidak bisa diakses?**
```bash
# Pastikan port 8080 tidak diblok
sudo iptables -I INPUT -p tcp --dport 8080 -j ACCEPT
```

---

## Author

**Levi** — [github.com/LEVI6957](https://github.com/LEVI6957)

> Project ini dirancang untuk **Linux (Ubuntu Server)**. Tidak dapat dijalankan langsung di Windows.
