# Suricata Auto Block Dashboard

Sistem deteksi & pemblokiran otomatis berbasis Suricata IDS, dilengkapi web dashboard real-time.

## Stack

| Service | Fungsi |
|---|---|
| **Suricata** | Network IDS — sniff traffic & tulis alert |
| **EveBox** | UI viewer alert Suricata |
| **auto_block** | Baca `eve.json`, blok IP via UFW otomatis |
| **dashboard** | Web UI custom: live feed, manage blocked IPs, webhook |

## Instalasi (Ubuntu Server)

```bash
git clone <repo-url>
cd test-suricata-main
sudo bash install.sh
```

Script otomatis mendeteksi IP server & network interface, install Docker + UFW, lalu menjalankan semua service.

## Konfigurasi

Edit `.env`:

```env
SERVER_IP=192.168.1.5      # IP server (dashboard hanya bisa diakses dari sini)
DASHBOARD_PORT=8080        # Port dashboard
NET_IFACE=ens33            # Network interface untuk Suricata
BLOCK_THRESHOLD=3          # Jumlah alert sebelum IP diblok
ALERT_SEVERITY=2           # 1=High only, 2=Medium+High, 3=Semua
WEBHOOK_URL=               # URL webhook notifikasi (opsional)
```

## Akses

| URL | Keterangan |
|---|---|
| `http://SERVER_IP:8080` | Dashboard custom (live feed + firewall control) |
| `http://SERVER_IP:5636` | EveBox (analisis alert detail) |

## Perintah Berguna

```bash
docker compose ps                    # Cek status semua service
docker compose logs -f auto_block    # Monitor proses auto-block
docker compose logs -f dashboard     # Log dashboard
docker compose restart               # Restart semua
docker compose down                  # Stop semua
```

## Webhook

Dukung Telegram, Discord, Slack, atau URL custom. Konfigurasi langsung dari panel **Webhook Notifikasi** di dashboard — tidak perlu restart.

## Struktur

```
├── docker-compose.yml
├── install.sh
├── .env
├── auto_block/
│   ├── auto_block.py    # Engine auto-block + notif dashboard
│   └── Dockerfile
├── dashboard/
│   ├── app.py           # FastAPI: REST + WebSocket + Webhook
│   ├── Dockerfile
│   ├── requirements.txt
│   └── static/
│       └── index.html   # UI dark theme
└── logs/                # eve.json dari Suricata
```
