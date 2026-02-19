FROM python:3.12-slim

LABEL description="Suricata Auto Block Dashboard"

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ufw \
    iptables \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY static/ ./static/

# Default settings file jika belum ada
RUN echo '{"webhook_url":"","webhook_headers":{},"threshold":3,"severity":2,"interval":10,"secret_token":""}' \
    > /app/settings.json

EXPOSE 8080

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]
