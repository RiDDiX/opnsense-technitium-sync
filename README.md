<p align="center">
  <img src="opnsensetechnitiumdnssync.png" alt="OPNsense Technitium DNS Sync" width="300">
</p>

<h1 align="center">OPNsense to Technitium DNS Sync</h1>

<p align="center">
  Automatically synchronize DHCP hostnames from OPNsense to Technitium DNS for local DNS resolution.
</p>

<p align="center">
  <a href="https://github.com/RiDDiX/opnsense-technitium-sync/actions"><img src="https://github.com/RiDDiX/opnsense-technitium-sync/actions/workflows/docker-publish.yml/badge.svg" alt="Docker Build"></a>
  <a href="https://github.com/RiDDiX/opnsense-technitium-sync/pkgs/container/opnsense-technitium-sync"><img src="https://img.shields.io/badge/ghcr.io-latest-blue" alt="GHCR"></a>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
</p>

---

## Overview

When running Technitium DNS on a separate device from OPNsense, DHCP clients that register their hostnames with OPNsense are not automatically resolvable via Technitium. This tool bridges that gap by periodically fetching DHCP leases and reservations from OPNsense and creating/updating A-records in a Technitium DNS zone.

**Supports:**
- **KEA DHCP** (modern OPNsense default)
- **Dnsmasq DHCP**
- **ISC DHCP** (legacy)
- **Unbound Host Overrides**
- **KEA Static Reservations**
- **Manual/static entries** via environment variable

## Quick Start

### Using the pre-built Docker image (recommended)

```yaml
# docker-compose.yml
version: '3.8'

services:
  dns-sync:
    image: ghcr.io/riddix/opnsense-technitium-sync:latest
    container_name: opnsense-technitium-sync
    env_file:
      - .env
    restart: unless-stopped
```

### Using a local build

```bash
git clone https://github.com/RiDDiX/opnsense-technitium-sync.git
cd opnsense-technitium-sync
cp .env.example .env
# Edit .env with your values
docker-compose up -d
```

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```env
# OPNsense API
OPNSENSE_URL=https://192.168.1.1
OPNSENSE_API_KEY=your-api-key
OPNSENSE_API_SECRET=your-api-secret
OPNSENSE_VERIFY_SSL=false

# Technitium DNS API
TECHNITIUM_URL=http://192.168.1.2:5380
TECHNITIUM_TOKEN=your-api-token

# Sync Settings
DNS_ZONE=home.arpa
SYNC_INTERVAL_MINUTES=5
LOG_LEVEL=INFO
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPNSENSE_URL` | OPNsense base URL (with https://) | `https://opnsense.home.arpa` |
| `OPNSENSE_API_KEY` | OPNsense API key | *required* |
| `OPNSENSE_API_SECRET` | OPNsense API secret | *required* |
| `OPNSENSE_VERIFY_SSL` | Verify SSL certificate | `false` |
| `TECHNITIUM_URL` | Technitium DNS base URL | `http://technitium.home.arpa:5380` |
| `TECHNITIUM_TOKEN` | Technitium API token | *required* |
| `DNS_ZONE` | DNS zone to manage | `home.arpa` |
| `SYNC_INTERVAL_MINUTES` | Sync interval in minutes | `5` |
| `LOG_LEVEL` | Log level (`DEBUG`, `INFO`, `WARNING`) | `INFO` |
| `STATIC_ENTRIES` | Manual static entries | *(empty)* |

### Static Entries

Devices without DHCP (e.g. printers, switches) can be added manually:

```env
STATIC_ENTRIES=printer=192.168.1.50,nas=192.168.1.10,switch=192.168.1.2
```

---

## API Permissions Setup

### OPNsense API Key

The sync tool needs **read-only** access to DHCP lease data.

#### Step 1: Create a dedicated API user (recommended)

1. Navigate to **System > Access > Users**
2. Click **+ Add** to create a new user
3. Set username (e.g. `api-dns-sync`) and a strong password
4. Save the user

#### Step 2: Assign minimum required permissions

1. Navigate to **System > Access > Groups**
2. Create a new group (e.g. `api-dns-sync`)
3. Add the API user to this group
4. Under **Assigned Privileges**, add the following permissions:

| Privilege | Why needed |
|-----------|-----------|
| `XMLRPC Library` | Required for all API access |
| `Status: DHCP Leases` | Read DHCP lease data (ISC/Dnsmasq) |
| `Services: Kea DHCP` | Read KEA DHCP leases and reservations |
| `Services: Unbound DNS` | Read Unbound host overrides (optional) |

> **Note:** If you are unsure which DHCP server you use, grant all three DHCP-related privileges. The sync tool auto-detects the active DHCP server.

#### Step 3: Generate API key

1. Go back to **System > Access > Users**
2. Click on the API user
3. Scroll down to **API keys** and click the **+** button
4. A `apikey.txt` file will be downloaded containing:
   - **Key** → use as `OPNSENSE_API_KEY`
   - **Secret** → use as `OPNSENSE_API_SECRET`

> **Security:** Store API credentials securely. Never commit the `.env` file to version control.

### Technitium DNS API Token

The sync tool needs **read/write** access to manage DNS records in your zone.

#### Step 1: Create an API token

1. Open the Technitium DNS admin panel (default: `http://<ip>:5380`)
2. Click on **Administration** in the left sidebar
3. Navigate to the **Sessions** tab
4. Click **Create API Token**
5. Set a descriptive name (e.g. `opnsense-sync`)
6. Copy the generated token → use as `TECHNITIUM_TOKEN`

#### Required permissions

The API token needs permission to:

| Action | API Endpoint | Why needed |
|--------|-------------|-----------|
| List zones | `GET /api/zones/list` | Check if target zone exists |
| Create zone | `GET /api/zones/create` | Create zone if missing (first run) |
| List records | `GET /api/zones/records` | Read current A-records for diff |
| Add records | `GET /api/zones/records/add` | Create new A-records |
| Delete records | `GET /api/zones/records/delete` | Remove stale records |

> **Tip:** The default admin token has full access. For production use, consider creating a scoped token if your Technitium version supports it.

#### Zone setup

The target zone (default `home.arpa`) will be **automatically created** if it does not exist. You can also create it manually:

1. Open Technitium DNS admin panel
2. Go to **Zones** > **Add Zone**
3. Zone: `home.arpa`, Type: **Primary Zone**

---

## Usage

### View logs

```bash
docker-compose logs -f
```

### Run a one-time sync manually

```bash
docker-compose exec dns-sync python sync.py --once
```

### Discover available OPNsense API endpoints

Useful for debugging when no leases are found:

```bash
docker-compose exec dns-sync python sync.py --discover
```

This tests all known DHCP API endpoints (KEA, Dnsmasq, ISC, Unbound) and reports which ones are available and what data they return.

---

## How It Works

```
┌──────────────┐         ┌──────────────────┐         ┌──────────────────┐
│   OPNsense   │  API    │   Sync Service   │  API    │  Technitium DNS  │
│  DHCP Server │ ──────> │  (this tool)     │ ──────> │   DNS Server     │
│              │         │                  │         │                  │
│ KEA/Dnsmasq/ │ Leases  │ - Fetch leases   │ Records │ - A records in   │
│ ISC DHCP     │ + Res.  │ - Compute diff   │ CRUD    │   home.arpa zone │
└──────────────┘         │ - Apply changes  │         └──────────────────┘
                         └──────────────────┘
```

1. **Fetch** DHCP leases + reservations from OPNsense (auto-detects KEA/Dnsmasq/ISC)
2. **Merge** with static entries from `STATIC_ENTRIES` env var
3. **Compare** with existing A-records in Technitium DNS zone
4. **Apply** changes: add new records, update changed IPs, remove stale entries
5. **Repeat** every `SYNC_INTERVAL_MINUTES` minutes

---

## Project Structure

```
opnsense-technitium-sync/
├── .github/
│   └── workflows/
│       └── docker-publish.yml   # GitHub Actions: build & push Docker image
├── docker-compose.yml           # Docker Compose configuration
├── Dockerfile                   # Container image definition
├── sync.py                      # Main sync script
├── entrypoint.sh                # Container entrypoint
├── requirements.txt             # Python dependencies
├── .env.example                 # Example configuration
└── README.md
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| No leases found | Run `--discover` to check which API endpoints respond. Ensure your API user has the required privileges. |
| API 401 Unauthorized | Check `OPNSENSE_API_KEY` and `OPNSENSE_API_SECRET` are correct. |
| API 404 Not Found | Your DHCP server type might differ. The tool auto-detects KEA, Dnsmasq, and ISC. |
| SSL certificate error | Set `OPNSENSE_VERIFY_SSL=false` for self-signed certificates. |
| Domain does not belong to zone | Ensure `DNS_ZONE` matches an existing zone in Technitium. |
| Zone not created | The API token may lack permissions. Create the zone manually in Technitium. |

## License

MIT License
