#!/bin/bash
set -e

# Setup cron if SYNC_INTERVAL_MINUTES is set
INTERVAL=${SYNC_INTERVAL_MINUTES:-5}

# Create cron job
echo "*/$INTERVAL * * * * cd /app && python sync.py --once >> /proc/1/fd/1 2>&1" > /etc/cron.d/dns-sync
chmod 0644 /etc/cron.d/dns-sync

# Start cron
cron

echo "DNS Sync started with ${INTERVAL} minute interval"
echo "OPNsense: $OPNSENSE_URL"
echo "Technitium: $TECHNITIUM_URL"
echo "Zone: $DNS_ZONE"

# Run once immediately
python sync.py --once || true

# Keep container running and log cron output
tail -f /var/log/syslog 2>/dev/null || tail -f /dev/null
