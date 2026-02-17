#!/usr/bin/env python3

import os
import sys
import time
import json
import logging
import argparse
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional
from dataclasses import dataclass, field
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
log = logging.getLogger(__name__)


@dataclass
class DnsEntry:
    hostname: str
    ip: str
    zone: str
    
    @property
    def fqdn(self) -> str:
        return f"{self.hostname}.{self.zone}"


@dataclass
class SyncState:
    last_sync: Optional[str] = None
    last_sync_success: bool = False
    next_sync: Optional[str] = None
    sync_count: int = 0
    error_count: int = 0
    last_error: Optional[str] = None
    records_added: int = 0
    records_updated: int = 0
    records_deleted: int = 0
    total_records: int = 0
    current_entries: List[Dict] = field(default_factory=list)
    dhcp_source: str = "unknown"
    opnsense_url: str = ""
    technitium_url: str = ""
    dns_zone: str = ""
    sync_interval: int = 5
    uptime_start: Optional[str] = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def to_dict(self) -> Dict:
        with self._lock:
            d = {
                'last_sync': self.last_sync,
                'last_sync_success': self.last_sync_success,
                'next_sync': self.next_sync,
                'sync_count': self.sync_count,
                'error_count': self.error_count,
                'last_error': self.last_error,
                'records_added': self.records_added,
                'records_updated': self.records_updated,
                'records_deleted': self.records_deleted,
                'total_records': self.total_records,
                'current_entries': self.current_entries,
                'dhcp_source': self.dhcp_source,
                'opnsense_url': self.opnsense_url,
                'technitium_url': self.technitium_url,
                'dns_zone': self.dns_zone,
                'sync_interval': self.sync_interval,
                'uptime_start': self.uptime_start,
            }
        return d


class LogBuffer(logging.Handler):
    def __init__(self, capacity=200):
        super().__init__()
        self.capacity = capacity
        self.buffer: List[Dict] = []
        self._lock = threading.Lock()

    def emit(self, record):
        entry = {
            'time': self.format(record),
            'level': record.levelname,
            'message': record.getMessage(),
        }
        with self._lock:
            self.buffer.append(entry)
            if len(self.buffer) > self.capacity:
                self.buffer = self.buffer[-self.capacity:]

    def get_logs(self, limit: int = 100) -> List[Dict]:
        with self._lock:
            return list(reversed(self.buffer[-limit:]))


sync_state = SyncState()
log_buffer = LogBuffer()
log_buffer.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(log_buffer)


class OPNsenseAPI:
    SEARCH_BODY = {"current": 1, "rowCount": -1, "searchPhrase": "", "sort": {}}
    
    def __init__(self, url: str, api_key: str, api_secret: str, verify_ssl: bool = False):
        self.base_url = url.rstrip('/')
        self.api_key = api_key
        self.api_secret = api_secret
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.auth = (api_key, api_secret)
    
    def _get(self, path: str) -> Optional[Dict]:
        url = f"{self.base_url}{path}"
        try:
            response = self.session.get(url, verify=self.verify_ssl, timeout=30)
            log.debug(f"GET {path} -> {response.status_code}")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            log.debug(f"GET {path} -> {e.response.status_code}")
            return None
        except Exception as e:
            log.debug(f"GET {path} -> Fehler: {e}")
            return None
    
    def _post_search(self, path: str) -> Optional[Dict]:
        url = f"{self.base_url}{path}"
        try:
            response = self.session.post(
                url, json=self.SEARCH_BODY, verify=self.verify_ssl, timeout=30
            )
            log.debug(f"POST {path} -> {response.status_code}")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            log.debug(f"POST {path} -> {e.response.status_code}")
            return None
        except Exception as e:
            log.debug(f"POST {path} -> Fehler: {e}")
            return None
    
    def _try_endpoint(self, path: str) -> Optional[Dict]:
        data = self._get(path)
        if data is not None:
            return data
        data = self._post_search(path)
        return data
    
    def discover_endpoints(self):
        endpoints = [
            # KEA
            ("GET",  "/api/kea/leases/search"),
            ("POST", "/api/kea/leases/search"),
            ("GET",  "/api/kea/dhcpv4/search_reservation"),
            ("POST", "/api/kea/dhcpv4/search_reservation"),
            ("GET",  "/api/kea/dhcpv4/search_subnet"),
            ("POST", "/api/kea/dhcpv4/search_subnet"),
            ("GET",  "/api/kea/dhcpv4/get"),
            ("GET",  "/api/kea/service/status"),
            # Dnsmasq
            ("GET",  "/api/dnsmasq/leases/searchLease"),
            ("POST", "/api/dnsmasq/leases/searchLease"),
            ("GET",  "/api/dnsmasq/settings/get"),
            # ISC DHCP (legacy)
            ("GET",  "/api/dhcpd/leases/searchLease"),
            ("POST", "/api/dhcpd/leases/searchLease"),
            # Unbound DNS (host overrides)
            ("GET",  "/api/unbound/settings/searchHostOverride"),
            ("POST", "/api/unbound/settings/searchHostOverride"),
        ]
        
        log.info("=== API Endpoint Discovery ===")
        for method, path in endpoints:
            url = f"{self.base_url}{path}"
            try:
                if method == "GET":
                    resp = self.session.get(url, verify=self.verify_ssl, timeout=10)
                else:
                    resp = self.session.post(url, json=self.SEARCH_BODY, verify=self.verify_ssl, timeout=10)
                
                status = resp.status_code
                body_preview = ""
                if status == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, dict):
                            keys = list(data.keys())
                            rows = data.get('rows', [])
                            body_preview = f" keys={keys} rows={len(rows)}"
                            if rows:
                                body_preview += f" sample_keys={list(rows[0].keys())}"
                        else:
                            body_preview = f" type={type(data).__name__}"
                    except Exception:
                        body_preview = f" body={resp.text[:200]}"
                
                symbol = "✓" if status == 200 else "✗"
                log.info(f"  {symbol} {method:4s} {path} -> {status}{body_preview}")
                
            except Exception as e:
                log.info(f"  ✗ {method:4s} {path} -> Fehler: {e}")
        
        log.info("=== Discovery Ende ===")
    
    def get_dhcp_leases(self) -> List[DnsEntry]:
        entries = self._get_kea_leases()
        if entries:
            self._last_dhcp_source = "KEA"
            return entries
        
        entries = self._get_dnsmasq_leases()
        if entries:
            self._last_dhcp_source = "Dnsmasq"
            return entries
        
        entries = self._get_isc_leases()
        if entries:
            self._last_dhcp_source = "ISC"
            return entries
        
        self._last_dhcp_source = "none"
        log.warning("Keine DHCP-Leases gefunden (KEA/Dnsmasq/ISC)")
        return []
    
    def _get_kea_leases(self) -> List[DnsEntry]:
        data = self._try_endpoint("/api/kea/leases/search")
        if data is None:
            return []
        
        rows = self._extract_rows(data)
        if rows:
            log.debug(f"KEA leases: {len(rows)} rows, sample: {json.dumps(rows[0], indent=2)}")
        
        entries = []
        for lease in rows:
            ip = self._extract_field(lease, ['address', 'ip_address', 'ip-address'])
            hostname = self._extract_field(lease, ['hostname', 'client_hostname', 'client-hostname'])
            
            state = str(lease.get('state', '')).lower()
            if state in ['expired', 'declined', 'released']:
                continue
            
            if not ip or not hostname or hostname == '*':
                continue
            
            hostname = self._sanitize_hostname(hostname)
            if hostname:
                entries.append(DnsEntry(hostname=hostname, ip=ip, zone=''))
        
        if entries:
            log.info(f"KEA Leases: {len(entries)} Einträge")
        return entries
    
    def _get_dnsmasq_leases(self) -> List[DnsEntry]:
        data = self._try_endpoint("/api/dnsmasq/leases/searchLease")
        if data is None:
            return []
        
        rows = self._extract_rows(data)
        if rows:
            log.debug(f"Dnsmasq leases: {len(rows)} rows, sample: {json.dumps(rows[0], indent=2)}")
        
        entries = []
        for lease in rows:
            ip = self._extract_field(lease, ['address', 'ip', 'ip_address'])
            hostname = self._extract_field(lease, ['hostname', 'client_hostname', 'host'])
            
            if not ip or not hostname or hostname == '*':
                continue
            
            hostname = self._sanitize_hostname(hostname)
            if hostname:
                entries.append(DnsEntry(hostname=hostname, ip=ip, zone=''))
        
        if entries:
            log.info(f"Dnsmasq Leases: {len(entries)} Einträge")
        return entries
    
    def _get_isc_leases(self) -> List[DnsEntry]:
        data = self._try_endpoint("/api/dhcpd/leases/searchLease")
        if data is None:
            return []
        
        rows = self._extract_rows(data)
        entries = []
        for lease in rows:
            if lease.get('online') != 'online':
                continue
            
            ip = self._extract_field(lease, ['address'])
            hostname = self._extract_field(lease, ['hostname'])
            
            if not ip or not hostname or hostname == '*':
                continue
            
            hostname = self._sanitize_hostname(hostname)
            if hostname:
                entries.append(DnsEntry(hostname=hostname, ip=ip, zone=''))
        
        if entries:
            log.info(f"ISC Leases: {len(entries)} Einträge")
        return entries
    
    def get_static_mappings(self) -> List[DnsEntry]:
        entries = []
        
        kea = self._get_kea_reservations()
        entries.extend(kea)
        
        unbound = self._get_unbound_host_overrides()
        entries.extend(unbound)
        
        if entries:
            log.info(f"Statische Mappings: {len(entries)} gefunden")
        return entries
    
    def _get_kea_reservations(self) -> List[DnsEntry]:
        data = self._post_search("/api/kea/dhcpv4/search_reservation")
        if data is None:
            return []
        
        rows = self._extract_rows(data)
        if rows:
            log.debug(f"KEA reservations: {len(rows)} rows, sample: {json.dumps(rows[0], indent=2)}")
        
        entries = []
        for res in rows:
            ip = self._extract_field(res, ['ip_address', 'address', 'ip-address'])
            hostname = self._extract_field(res, ['hostname', 'client_hostname', 'description'])
            
            if not ip or not hostname or hostname == '*':
                continue
            
            hostname = self._sanitize_hostname(hostname)
            if hostname:
                entries.append(DnsEntry(hostname=hostname, ip=ip, zone=''))
        
        if entries:
            log.info(f"KEA Reservations: {len(entries)} Einträge")
        return entries
    
    def _get_unbound_host_overrides(self) -> List[DnsEntry]:
        data = self._try_endpoint("/api/unbound/settings/searchHostOverride")
        if data is None:
            return []
        
        rows = self._extract_rows(data)
        if rows:
            log.debug(f"Unbound overrides: {len(rows)} rows, sample: {json.dumps(rows[0], indent=2)}")
        
        entries = []
        for row in rows:
            ip = self._extract_field(row, ['server', 'ip', 'address', 'rr'])
            hostname = self._extract_field(row, ['hostname', 'host', 'name'])
            domain = self._extract_field(row, ['domain', 'zone'])
            
            if not ip or not hostname:
                continue
            
            hostname = self._sanitize_hostname(hostname)
            if hostname:
                entries.append(DnsEntry(hostname=hostname, ip=ip, zone=domain or ''))
        
        if entries:
            log.info(f"Unbound Host Overrides: {len(entries)} Einträge")
        return entries
    
    @staticmethod
    def _extract_rows(data: Dict) -> List[Dict]:
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get('rows', []) or data.get('leases', []) or []
        return []
    
    @staticmethod
    def _extract_field(row: Dict, keys: List[str]) -> str:
        for key in keys:
            val = row.get(key, '')
            if val:
                return str(val).strip().lower()
        return ''
    
    @staticmethod
    def _sanitize_hostname(hostname: str) -> str:
        sanitized = ''.join(c if c.isalnum() or c == '-' else '-' for c in hostname)
        return sanitized.strip('-')[:63]


class TechnitiumAPI:
    def __init__(self, url: str, token: str):
        self.base_url = url.rstrip('/')
        self.token = token
        self.session = requests.Session()
    
    def _api_call(self, path: str, params: Optional[Dict] = None) -> Dict:
        url = f"{self.base_url}/api{path}"
        
        if params is None:
            params = {}
        params['token'] = self.token
        
        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            log.error(f"Technitium API Fehler: {e}")
            return {'status': 'error', 'errorMessage': str(e)}
    
    def list_zones(self) -> List[Dict]:
        result = self._api_call('/zones/list')
        return result.get('response', {}).get('zones', [])
    
    def zone_exists(self, zone_name: str) -> bool:
        zones = self.list_zones()
        return any(z.get('name') == zone_name for z in zones)
    
    def create_zone(self, zone_name: str) -> bool:
        params = {
            'zone': zone_name,
            'type': 'Primary'
        }
        result = self._api_call('/zones/create', params)
        
        if result.get('status') == 'ok':
            log.info(f"Zone {zone_name} erstellt")
            return True
        else:
            log.error(f"Konnte Zone nicht erstellen: {result}")
            return False
    
    def get_records(self, zone_name: str) -> List[Dict]:
        params = {'zone': zone_name}
        result = self._api_call('/zones/records', params)
        
        if result.get('status') == 'ok':
            return result.get('response', {}).get('records', [])
        return []
    
    def get_a_records(self, zone_name: str) -> Dict[str, str]:
        records = self.get_records(zone_name)
        a_records = {}
        
        for record in records:
            if record.get('type') == 'A':
                name = record.get('name', '').lower()
                ip = record.get('value', '')
                short_name = name.replace(f'.{zone_name}', '').replace(zone_name, '')
                a_records[short_name] = ip
        
        return a_records
    
    def add_record(self, zone_name: str, name: str, record_type: str, value: str, ttl: int = 300) -> bool:
        if name and name != '@':
            fqdn = f"{name}.{zone_name}"
        else:
            fqdn = zone_name
        
        params = {
            'zone': zone_name,
            'domain': fqdn,
            'type': record_type,
            'value': value,
            'ttl': ttl
        }
        
        result = self._api_call('/zones/records/add', params)
        
        if result.get('status') == 'ok':
            log.debug(f"Record hinzugefügt: {name}.{zone_name} -> {value}")
            return True
        else:
            log.error(f"Konnte Record nicht hinzufügen: {result}")
            return False
    
    def delete_record(self, zone_name: str, name: str, record_type: str, value: Optional[str] = None) -> bool:
        if name and name != '@':
            fqdn = f"{name}.{zone_name}"
        else:
            fqdn = zone_name
        
        params = {
            'zone': zone_name,
            'domain': fqdn,
            'type': record_type
        }
        if value:
            params['value'] = value
        
        result = self._api_call('/zones/records/delete', params)
        
        if result.get('status') == 'ok':
            log.debug(f"Record gelöscht: {name}.{zone_name}")
            return True
        else:
            log.error(f"Konnte Record nicht löschen: {result}")
            return False
    
    def update_record(self, zone_name: str, name: str, record_type: str, new_value: str, ttl: int = 300) -> bool:
        self.delete_record(zone_name, name, record_type)
        return self.add_record(zone_name, name, record_type, new_value, ttl)


class DNSSync:
    def __init__(self):
        self.opnsense_url = os.getenv('OPNSENSE_URL', 'https://opnsense.home.arpa')
        self.opnsense_key = os.getenv('OPNSENSE_API_KEY', '')
        self.opnsense_secret = os.getenv('OPNSENSE_API_SECRET', '')
        self.opnsense_verify_ssl = os.getenv('OPNSENSE_VERIFY_SSL', 'false').lower() == 'true'
        self.technitium_url = os.getenv('TECHNITIUM_URL', 'http://technitium.home.arpa:5380')
        self.technitium_token = os.getenv('TECHNITIUM_TOKEN', '')
        self.dns_zone = os.getenv('DNS_ZONE', 'home.arpa')
        self.sync_interval = int(os.getenv('SYNC_INTERVAL_MINUTES', '5'))
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
        self.static_entries_str = os.getenv('STATIC_ENTRIES', '')
        self.dashboard_enabled = os.getenv('DASHBOARD_ENABLED', 'true').lower() == 'true'
        self.dashboard_port = int(os.getenv('DASHBOARD_PORT', '8099'))
        
        logging.getLogger().setLevel(getattr(logging, self.log_level.upper()))
        
        sync_state.opnsense_url = self.opnsense_url
        sync_state.technitium_url = self.technitium_url
        sync_state.dns_zone = self.dns_zone
        sync_state.sync_interval = self.sync_interval
        sync_state.uptime_start = datetime.now(timezone.utc).isoformat()
        
        self.opnsense = None
        self.technitium = None
    
    def validate_config(self):
        if not self.opnsense_key or not self.opnsense_secret:
            log.error("OPNSENSE_API_KEY und OPNSENSE_API_SECRET müssen gesetzt sein")
            return False
        
        if not self.technitium_token:
            log.error("TECHNITIUM_TOKEN muss gesetzt sein")
            return False
        
        return True
    
    def initialize(self):
        self.opnsense = OPNsenseAPI(
            self.opnsense_url,
            self.opnsense_key,
            self.opnsense_secret,
            self.opnsense_verify_ssl
        )
        self.technitium = TechnitiumAPI(
            self.technitium_url,
            self.technitium_token
        )
    
    def parse_static_entries(self) -> List[DnsEntry]:
        entries = []
        if not self.static_entries_str:
            return entries
        
        for entry in self.static_entries_str.split(','):
            entry = entry.strip()
            if '=' in entry:
                hostname, ip = entry.split('=', 1)
                hostname = hostname.strip().lower()
                ip = ip.strip()
                
                if hostname and ip:
                    entries.append(DnsEntry(
                        hostname=hostname,
                        ip=ip,
                        zone=''
                    ))
        
        return entries
    
    def sync(self) -> bool:
        log.info(f"=== Sync Start === Zone: {self.dns_zone}")
        
        try:
            dhcp_entries = self.opnsense.get_dhcp_leases()
            static_mappings = self.opnsense.get_static_mappings()
            manual_entries = self.parse_static_entries()
            
            if dhcp_entries:
                with sync_state._lock:
                    sync_state.dhcp_source = getattr(self.opnsense, '_last_dhcp_source', 'unknown')
            
            all_entries = {}
            for entry in dhcp_entries + static_mappings + manual_entries:
                all_entries[entry.hostname] = entry
            
            entries = list(all_entries.values())
            log.info(f"Gesamt: {len(entries)} eindeutige Einträge")
            
            if not entries:
                log.warning("Keine Einträge zu synchronisieren")
                with sync_state._lock:
                    sync_state.last_sync = datetime.now(timezone.utc).isoformat()
                    sync_state.last_sync_success = True
                    sync_state.sync_count += 1
                    sync_state.total_records = 0
                    sync_state.current_entries = []
                return True
            
            if not self.technitium.zone_exists(self.dns_zone):
                log.info(f"Zone {self.dns_zone} existiert nicht, erstelle...")
                if not self.technitium.create_zone(self.dns_zone):
                    return False
            
            current_records = self.technitium.get_a_records(self.dns_zone)
            log.info(f"Technitium: {len(current_records)} existierende A-Records")
            
            desired_records = {e.hostname: e.ip for e in entries}
            to_add, to_update, to_delete = [], [], []
            
            for hostname, ip in desired_records.items():
                if hostname not in current_records:
                    to_add.append((hostname, ip))
                elif current_records[hostname] != ip:
                    to_update.append((hostname, ip))
            
            opnsense_hostnames = set(desired_records.keys())
            manual_hostnames = {e.hostname for e in manual_entries}
            for hostname in current_records:
                if hostname not in opnsense_hostnames and hostname not in manual_hostnames:
                    to_delete.append(hostname)
            
            for hostname, ip in to_add:
                log.info(f"Hinzufügen: {hostname}.{self.dns_zone} -> {ip}")
                self.technitium.add_record(self.dns_zone, hostname, 'A', ip)
            
            for hostname, ip in to_update:
                log.info(f"Aktualisieren: {hostname}.{self.dns_zone} -> {ip}")
                self.technitium.update_record(self.dns_zone, hostname, 'A', ip)
            
            for hostname in to_delete:
                if hostname in ('@', 'ns', 'www', 'mail'):
                    continue
                else:
                    log.info(f"Löschen: {hostname}.{self.dns_zone}")
                    self.technitium.delete_record(self.dns_zone, hostname, 'A')
            
            log.info(f"Sync complete: +{len(to_add)} ~{len(to_update)} -{len(to_delete)}")
            
            with sync_state._lock:
                sync_state.last_sync = datetime.now(timezone.utc).isoformat()
                sync_state.last_sync_success = True
                sync_state.sync_count += 1
                sync_state.records_added = len(to_add)
                sync_state.records_updated = len(to_update)
                sync_state.records_deleted = len(to_delete)
                sync_state.total_records = len(entries)
                sync_state.current_entries = sorted(
                    [{'hostname': e.hostname, 'ip': e.ip, 'fqdn': f"{e.hostname}.{self.dns_zone}"} for e in entries],
                    key=lambda x: x['hostname']
                )
            
            return True
            
        except Exception as e:
            log.exception(f"Sync fehlgeschlagen: {e}")
            with sync_state._lock:
                sync_state.last_sync = datetime.now(timezone.utc).isoformat()
                sync_state.last_sync_success = False
                sync_state.error_count += 1
                sync_state.last_error = str(e)
            return False
    
    def run(self, once: bool = False, discover: bool = False):
        if not self.validate_config():
            sys.exit(1)
        
        self.initialize()
        
        if discover:
            logging.getLogger().setLevel(logging.DEBUG)
            self.opnsense.discover_endpoints()
            sys.exit(0)
        
        if once:
            log.info("Einmalige Synchronisation...")
            success = self.sync()
            sys.exit(0 if success else 1)
        
        if self.dashboard_enabled:
            dashboard_thread = threading.Thread(
                target=start_dashboard,
                args=(self.dashboard_port,),
                daemon=True
            )
            dashboard_thread.start()
            log.info(f"Dashboard gestartet auf Port {self.dashboard_port}")
        
        log.info(f"DNS Sync gestartet - Intervall: {self.sync_interval} Minuten")
        
        while True:
            success = self.sync()
            
            next_time = datetime.now(timezone.utc).timestamp() + (self.sync_interval * 60)
            with sync_state._lock:
                sync_state.next_sync = datetime.fromtimestamp(next_time, tz=timezone.utc).isoformat()
            
            if success:
                log.info(f"Nächster Sync in {self.sync_interval} Minuten...")
            else:
                log.warning("Sync fehlgeschlagen, retry in 1 Minute...")
                time.sleep(60)
                continue
            
            time.sleep(self.sync_interval * 60)


# --- Dashboard ---

def create_dashboard_app():
    from flask import Flask, jsonify, Response
    
    app = Flask(__name__)
    
    # Suppress Flask request logging in production
    flask_log = logging.getLogger('werkzeug')
    flask_log.setLevel(logging.WARNING)
    
    DASHBOARD_HTML = get_dashboard_html()
    
    @app.route('/')
    def index():
        return Response(DASHBOARD_HTML, mimetype='text/html')
    
    @app.route('/api/status')
    def api_status():
        return jsonify(sync_state.to_dict())
    
    @app.route('/api/logs')
    def api_logs():
        return jsonify(log_buffer.get_logs(limit=100))
    
    @app.route('/health')
    def health():
        return jsonify({'status': 'ok'})
    
    return app


def start_dashboard(port):
    app = create_dashboard_app()
    app.run(host='0.0.0.0', port=port, threaded=True)


def get_dashboard_html():
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OPNsense Technitium DNS Sync</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        brand: { 50: '#eff6ff', 100: '#dbeafe', 500: '#3b82f6', 600: '#2563eb', 700: '#1d4ed8', 900: '#1e3a5f' }
                    }
                }
            }
        }
    </script>
    <style>
        body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }
        .fade-in { animation: fadeIn 0.3s ease-in; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
        .log-line { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.75rem; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #1e293b; }
        ::-webkit-scrollbar-thumb { background: #475569; border-radius: 3px; }
    </style>
</head>
<body class="dark bg-slate-950 text-slate-200 min-h-screen">
    <div class="max-w-7xl mx-auto px-4 py-6">
        <!-- Header -->
        <div class="flex items-center justify-between mb-8">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 bg-brand-600 rounded-lg flex items-center justify-center">
                    <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                    </svg>
                </div>
                <div>
                    <h1 class="text-xl font-bold text-white">DNS Sync Dashboard</h1>
                    <p class="text-sm text-slate-400">OPNsense &rarr; Technitium DNS</p>
                </div>
            </div>
            <div class="flex items-center gap-3">
                <span id="status-badge" class="px-3 py-1 rounded-full text-xs font-medium bg-slate-700 text-slate-300">Loading...</span>
                <span class="text-xs text-slate-500" id="refresh-timer">Auto-refresh: 15s</span>
            </div>
        </div>

        <!-- Stats Cards -->
        <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 mb-6">
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <p class="text-xs text-slate-400 uppercase tracking-wider">Total Records</p>
                <p class="text-2xl font-bold text-white mt-1" id="total-records">-</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <p class="text-xs text-slate-400 uppercase tracking-wider">Last Added</p>
                <p class="text-2xl font-bold text-emerald-400 mt-1" id="records-added">-</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <p class="text-xs text-slate-400 uppercase tracking-wider">Last Updated</p>
                <p class="text-2xl font-bold text-amber-400 mt-1" id="records-updated">-</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <p class="text-xs text-slate-400 uppercase tracking-wider">Last Deleted</p>
                <p class="text-2xl font-bold text-red-400 mt-1" id="records-deleted">-</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <p class="text-xs text-slate-400 uppercase tracking-wider">Sync Count</p>
                <p class="text-2xl font-bold text-brand-500 mt-1" id="sync-count">-</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <p class="text-xs text-slate-400 uppercase tracking-wider">Errors</p>
                <p class="text-2xl font-bold text-red-400 mt-1" id="error-count">-</p>
            </div>
        </div>

        <!-- Info Bar -->
        <div class="bg-slate-900 border border-slate-800 rounded-xl p-4 mb-6 grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div><span class="text-slate-400">Zone:</span> <span class="text-white font-mono" id="dns-zone">-</span></div>
            <div><span class="text-slate-400">Source:</span> <span class="text-white" id="dhcp-source">-</span></div>
            <div><span class="text-slate-400">Last Sync:</span> <span class="text-white" id="last-sync">-</span></div>
            <div><span class="text-slate-400">Next Sync:</span> <span class="text-white" id="next-sync">-</span></div>
        </div>

        <!-- Main Content: Records + Logs -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <!-- DNS Records Table -->
            <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <div class="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
                    <h2 class="text-sm font-semibold text-white">DNS Records</h2>
                    <div class="flex items-center gap-2">
                        <input type="text" id="search-records" placeholder="Filter..."
                            class="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 w-40">
                        <span class="text-xs text-slate-400" id="records-count">0 records</span>
                    </div>
                </div>
                <div class="overflow-y-auto max-h-[500px]">
                    <table class="w-full text-sm">
                        <thead class="bg-slate-800/50 sticky top-0">
                            <tr>
                                <th class="text-left px-4 py-2 text-xs text-slate-400 font-medium">Hostname</th>
                                <th class="text-left px-4 py-2 text-xs text-slate-400 font-medium">IP Address</th>
                                <th class="text-left px-4 py-2 text-xs text-slate-400 font-medium">FQDN</th>
                            </tr>
                        </thead>
                        <tbody id="records-table" class="divide-y divide-slate-800/50">
                            <tr><td colspan="3" class="px-4 py-8 text-center text-slate-500">Waiting for first sync...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Logs Panel -->
            <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <div class="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
                    <h2 class="text-sm font-semibold text-white">Recent Logs</h2>
                    <select id="log-filter" class="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1 text-xs text-white focus:outline-none">
                        <option value="all">All</option>
                        <option value="ERROR">Errors</option>
                        <option value="WARNING">Warnings</option>
                        <option value="INFO">Info</option>
                    </select>
                </div>
                <div class="overflow-y-auto max-h-[500px] p-2" id="logs-container">
                    <p class="text-slate-500 text-xs p-2">Waiting for logs...</p>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div class="mt-6 text-center text-xs text-slate-600">
            OPNsense Technitium DNS Sync &middot;
            <a href="https://github.com/RiDDiX/opnsense-technitium-sync" target="_blank" class="text-slate-500 hover:text-brand-500">GitHub</a>
            &middot;
            <a href="https://www.paypal.me/RiDDiX93" target="_blank" class="text-slate-500 hover:text-brand-500">☕ Buy me a coffee</a>
        </div>
    </div>

    <script>
        const REFRESH_INTERVAL = 15000;
        let searchFilter = '';
        let logFilter = 'all';

        document.getElementById('search-records').addEventListener('input', (e) => {
            searchFilter = e.target.value.toLowerCase();
            renderRecords(lastEntries);
        });
        document.getElementById('log-filter').addEventListener('change', (e) => {
            logFilter = e.target.value;
            renderLogs(lastLogs);
        });

        let lastEntries = [];
        let lastLogs = [];

        function formatTime(isoStr) {
            if (!isoStr) return '-';
            const d = new Date(isoStr);
            return d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) +
                   ' ' + d.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit' });
        }

        function renderRecords(entries) {
            lastEntries = entries;
            const tbody = document.getElementById('records-table');
            const filtered = entries.filter(e =>
                !searchFilter ||
                e.hostname.includes(searchFilter) ||
                e.ip.includes(searchFilter) ||
                e.fqdn.includes(searchFilter)
            );
            document.getElementById('records-count').textContent = filtered.length + ' records';

            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan="3" class="px-4 py-8 text-center text-slate-500">No records found</td></tr>';
                return;
            }
            tbody.innerHTML = filtered.map(e => `
                <tr class="hover:bg-slate-800/50 transition-colors">
                    <td class="px-4 py-2 font-mono text-emerald-400 text-xs">${e.hostname}</td>
                    <td class="px-4 py-2 font-mono text-slate-300 text-xs">${e.ip}</td>
                    <td class="px-4 py-2 font-mono text-slate-500 text-xs">${e.fqdn}</td>
                </tr>
            `).join('');
        }

        function levelColor(level) {
            switch(level) {
                case 'ERROR': return 'text-red-400';
                case 'WARNING': return 'text-amber-400';
                case 'DEBUG': return 'text-slate-500';
                default: return 'text-slate-300';
            }
        }

        function levelBadge(level) {
            const colors = {
                'ERROR': 'bg-red-900/50 text-red-400',
                'WARNING': 'bg-amber-900/50 text-amber-400',
                'INFO': 'bg-slate-800 text-slate-400',
                'DEBUG': 'bg-slate-800/50 text-slate-600',
            };
            return colors[level] || colors['INFO'];
        }

        function renderLogs(logs) {
            lastLogs = logs;
            const container = document.getElementById('logs-container');
            const filtered = logFilter === 'all' ? logs : logs.filter(l => l.level === logFilter);

            if (filtered.length === 0) {
                container.innerHTML = '<p class="text-slate-500 text-xs p-2">No logs matching filter</p>';
                return;
            }
            container.innerHTML = filtered.map(l => `
                <div class="log-line flex items-start gap-2 px-2 py-1 rounded hover:bg-slate-800/50 ${levelColor(l.level)}">
                    <span class="shrink-0 px-1.5 py-0.5 rounded text-[10px] font-medium ${levelBadge(l.level)}">${l.level}</span>
                    <span class="break-all">${l.message}</span>
                </div>
            `).join('');
        }

        async function refresh() {
            try {
                const [statusRes, logsRes] = await Promise.all([
                    fetch('/api/status'),
                    fetch('/api/logs')
                ]);
                const status = await statusRes.json();
                const logs = await logsRes.json();

                // Update stats
                document.getElementById('total-records').textContent = status.total_records;
                document.getElementById('records-added').textContent = '+' + status.records_added;
                document.getElementById('records-updated').textContent = '~' + status.records_updated;
                document.getElementById('records-deleted').textContent = '-' + status.records_deleted;
                document.getElementById('sync-count').textContent = status.sync_count;
                document.getElementById('error-count').textContent = status.error_count;

                // Info bar
                document.getElementById('dns-zone').textContent = status.dns_zone;
                document.getElementById('dhcp-source').textContent = status.dhcp_source;
                document.getElementById('last-sync').textContent = formatTime(status.last_sync);
                document.getElementById('next-sync').textContent = formatTime(status.next_sync);

                // Status badge
                const badge = document.getElementById('status-badge');
                if (status.last_sync_success) {
                    badge.textContent = 'Healthy';
                    badge.className = 'px-3 py-1 rounded-full text-xs font-medium bg-emerald-900/50 text-emerald-400 border border-emerald-800';
                } else if (status.last_sync === null) {
                    badge.textContent = 'Waiting...';
                    badge.className = 'px-3 py-1 rounded-full text-xs font-medium bg-slate-700 text-slate-300';
                } else {
                    badge.textContent = 'Error';
                    badge.className = 'px-3 py-1 rounded-full text-xs font-medium bg-red-900/50 text-red-400 border border-red-800';
                }

                renderRecords(status.current_entries || []);
                renderLogs(logs || []);
            } catch (err) {
                console.error('Refresh failed:', err);
            }
        }

        refresh();
        setInterval(refresh, REFRESH_INTERVAL);
    </script>
</body>
</html>'''


def main():
    parser = argparse.ArgumentParser(description='OPNsense zu TechnitiumDNS Sync')
    parser.add_argument('--once', action='store_true', help='Einmalige Synchronisation')
    parser.add_argument('--discover', action='store_true', help='Teste alle bekannten API-Endpunkte')
    args = parser.parse_args()
    
    sync = DNSSync()
    sync.run(once=args.once, discover=args.discover)


if __name__ == '__main__':
    main()
