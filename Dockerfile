FROM python:3.12-slim

WORKDIR /app

# Install cron for periodic sync
RUN apt-get update && apt-get install -y cron && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sync.py .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["./entrypoint.sh"]
