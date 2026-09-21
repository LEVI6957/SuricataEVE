# Suricata Auto Block Dashboard

Sebuah sistem deteksi dan pemblokiran IP otomatis berbasis **Suricata IDS**, yang dilengkapi dengan web dashboard untuk memonitor dan mengatur konfigurasi secara langsung.

Sistem ini dirancang untuk berjalan di atas **Docker**, sehingga tidak memerlukan instalasi Suricata secara manual di OS host (kecuali konfigurasi iptables).

---

## Komponen Sistem

| Service | Fungsi |
|---|---|
| **Suricata 8.x** | Network IDS — Melakukan sniffing pada *traffic* jaringan dan menulis *alert* ke `eve.json` |
| **EveBox**       | UI untuk melihat detail *alert* dari Suricata secara mendalam |
| **auto_block**   | Membaca `eve.json` secara *real-time* dan memblokir IP via **iptables** jika mencapai batas *threshold* |
| **dashboard**    | Web UI: memantau *alert*, mengelola daftar IP terblokir, mengatur *whitelist*, dan mengonfigurasi *webhook* |

> **Catatan Teknis:** Aturan pemblokiran menggunakan *custom chain* iptables bernama `SURICATA_BLOCK`. Pemisahan ini dilakukan agar aturan tidak tumpang tindih dengan aturan *firewall* bawaan sistem (seperti UFW).

---

## Instalasi (Ubuntu Server)

### Prasyarat
- Ubuntu 20.04 / 22.04 / 24.04
- Disarankan dijalankan pada sistem operasi yang masih bersih (*fresh install*).

### Langkah Instalasi

1. Clone repositori ini:
   ```bash
   git clone https://github.com/LEVI6957/SuricataEVE.git
   cd SuricataEVE
   ```
2. Jalankan skrip instalasi (memerlukan akses `sudo`):
   ```bash
   sudo bash install.sh
   ```
3. Skrip `install.sh` akan melakukan instalasi Docker, membuat file konfigurasi `.env`, menerapkan aturan iptables dan UFW, serta menjalankan Docker Compose.

---

## Setup Awal (Setup Wizard)

Setelah skrip instalasi selesai dijalankan, Anda harus melakukan *Setup* awal melalui Dashboard:

1. Buka browser dan akses: `http://<IP_SERVER>:8080`
2. Halaman **Setup Wizard** akan muncul secara otomatis untuk instalasi baru.
3. Anda akan diminta untuk mengatur:
   - **Username & Password** untuk login administrator.
   - **Batas Threshold** (jumlah alert sebelum IP diblokir).
   - **Batas Severity** (keparahan alert yang dicatat).
   - **Notifikasi Webhook** (Discord / Telegram) — Opsional.
4. Setelah diselesaikan, konfigurasi akan disimpan ke `settings.json` dan Anda dapat *login* ke Dashboard.

> **Catatan Konfigurasi:** Jika Anda ingin mengubah *Threshold*, *Severity*, atau pengaturan *Webhook* di kemudian hari, Anda cukup melakukannya dari menu **Settings** di dalam Dashboard (tanpa perlu melakukan *restart* pada layanan).

---

## Akses Layanan

| URL | Keterangan |
|---|---|
| `http://<IP_SERVER>:8080` | Dashboard Utama (Memonitor *alert* & kontrol *firewall*) |
| `http://<IP_SERVER>:5636` | EveBox (Pencarian & Analisis detail log) |

> **Penting terkait Keamanan (EveBox):** Skrip instalasi menggunakan `ufw deny` pada port 5636 secara *default*. Ini berarti EveBox **tidak bisa** diakses secara publik demi keamanan, karena EveBox di-deploy tanpa fitur otentikasi. Jika Anda ingin mengaksesnya, Anda dapat melakukan SSH Tunneling ke port 5636 atau membuka *port* pada UFW jika Anda yakin jaringannya aman (`sudo ufw allow 5636/tcp`).

---

## Fitur Utama

- **Live Feed** — *Alert* dari Suricata ditampilkan di Dashboard secara *real-time* via WebSocket.
- **Manajemen IP** — Melihat daftar IP yang sedang diblokir beserta kemampuan untuk membuka blokir (Unblock) langsung dari UI.
- **Whitelist** — Fitur untuk mendaftarkan alamat IP yang tidak boleh diblokir oleh sistem (mendukung input banyak IP sekaligus).
- **Pengaturan Dinamis** — Perubahan nilai *Threshold*, *Severity*, dan *Webhook* dari Dashboard akan langsung diterapkan (*on-the-fly*) oleh *auto_block* tanpa jeda.
- **Atomic Saving** — Penyimpanan konfigurasi di-handle menggunakan metode penulisan atomik untuk mencegah berkas `settings.json` menjadi korup ketika aplikasi terhenti mendadak.
- **Brute Force Guard** — Perlindungan keamanan akses Dashboard: jika terjadi percobaan *login* gagal sebanyak 5 kali berturut-turut, alamat IP pengunjung akan otomatis diblokir.

---

## Notifikasi Webhook

Sistem mendukung pengiriman notifikasi terpusat ketika terjadi kejadian (*event*) penting.

Event yang akan memicu pengiriman pesan:
- `BLOCKED` — Alamat IP baru saja diblokir oleh iptables.
- `UNBLOCKED` — Alamat IP dibebaskan secara manual dari Dashboard.
- `HIGH_ALERT` — Terdapat *alert* dengan tingkat keparahan tinggi.
- `BRUTE FORCE` — Percobaan login berulang yang gagal.
- `LOGIN` — Administrator berhasil masuk ke Dashboard.
- `WHITELIST_ADD/REMOVE` — Alamat IP ditambahkan atau dihapus dari daftar *whitelist*.

Konfigurasi untuk **Discord** atau **Telegram** dapat diatur melalui halaman **Settings**.

---

## Perintah Manajemen

Berikut adalah perintah-perintah yang mungkin Anda butuhkan untuk memantau server:

```bash
# Mengecek status container Docker
docker compose ps

# Melihat log auto_block secara real-time
docker compose logs -f auto_block

# Melihat log Dashboard secara real-time
docker compose logs -f dashboard

# Memeriksa daftar IP yang saat ini diblokir langsung dari iptables OS host
sudo iptables -n -L SURICATA_BLOCK --line-numbers

# Melakukan uninstalasi dan menghapus seluruh konfigurasi
sudo bash uninstall.sh
```

---

## Lisensi

Proyek ini berada di bawah Lisensi MIT. Lihat file [LICENSE](LICENSE) untuk informasi lebih lanjut.

## Author

**Levi** — [@LEVI6957](https://github.com/LEVI6957)
