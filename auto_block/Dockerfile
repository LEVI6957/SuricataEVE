# Dockerfile untuk service auto_block
FROM python:3.12-slim

LABEL maintainer="auto_block"
LABEL description="Suricata Auto Firewall Blocking menggunakan UFW"

WORKDIR /app

# Install UFW dan dependensi sistem
RUN apt-get update && apt-get install -y --no-install-recommends \
    ufw \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Salin script
COPY auto_block.py /app/auto_block.py

# Install Python dependency untuk notifikasi ke dashboard
RUN pip install --no-cache-dir httpx

# Buat file log kosong
RUN touch /app/blocked_ips.log

# Jalankan script
CMD ["python3", "-u", "/app/auto_block.py"]
