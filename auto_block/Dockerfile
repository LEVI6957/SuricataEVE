# Dockerfile untuk service auto_block (iptables mode)
FROM python:3.12-slim

LABEL maintainer="auto_block"
LABEL description="Suricata Auto Firewall Blocking menggunakan iptables"

WORKDIR /app

# Install iptables dan dependensi sistem
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Salin script
COPY auto_block.py /app/auto_block.py


# Buat file log dan state kosong
RUN touch /app/blocked_ips.log /app/alert_counts.json

# Jalankan script
CMD ["python3", "-u", "/app/auto_block.py"]
