#!/bin/bash
set -e

echo "OPNsense: $OPNSENSE_URL -> Technitium: $TECHNITIUM_URL"
echo "Zone: $DNS_ZONE | Interval: ${SYNC_INTERVAL_MINUTES:-5}m | Dashboard: ${DASHBOARD_ENABLED:-true} :${DASHBOARD_PORT:-8099}"

exec python sync.py
