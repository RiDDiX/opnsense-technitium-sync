#!/bin/bash
set -e

echo "=== OPNsense Technitium DNS Sync ==="
echo "OPNsense:  $OPNSENSE_URL"
echo "Technitium: $TECHNITIUM_URL"
echo "Zone:       $DNS_ZONE"
echo "Interval:   ${SYNC_INTERVAL_MINUTES:-5} min"
echo "Dashboard:  ${DASHBOARD_ENABLED:-true} (port ${DASHBOARD_PORT:-8099})"
echo "======================================"

# Run in continuous mode (built-in scheduler + dashboard)
exec python sync.py
