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
        params = {'zone': zone_name, 'domain': zone_name, 'listZone': 'true'}
        result = self._api_call('/zones/records/get', params)
        
        if result.get('status') == 'ok':
            return result.get('response', {}).get('records', [])
        log.warning(f"Konnte Records nicht abrufen: {result.get('errorMessage', 'unbekannt')}")
        return []
    
    def get_a_records(self, zone_name: str) -> Dict[str, str]:
        records = self.get_records(zone_name)
        a_records = {}
        zone_suffix = '.' + zone_name
        
        for record in records:
            if record.get('type') != 'A':
                continue
            name = record.get('name', '').lower()
            ip = record.get('rData', {}).get('ipAddress', '')
            if not ip:
                continue
            
            if name.endswith(zone_suffix):
                short_name = name[:-(len(zone_suffix))]
            elif name == zone_name:
                short_name = '@'
            else:
                continue
            
            if short_name:
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
        
        err = result.get('errorMessage', '')
        if 'already exists' in err:
            log.debug(f"Record existiert bereits: {name}.{zone_name} -> {value}")
            return True
        
        log.error(f"Konnte Record nicht hinzufügen: {err}")
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
            
            errors = 0
            
            for hostname, ip in to_add:
                log.info(f"Hinzufügen: {hostname}.{self.dns_zone} -> {ip}")
                if not self.technitium.add_record(self.dns_zone, hostname, 'A', ip):
                    errors += 1
            
            for hostname, ip in to_update:
                log.info(f"Aktualisieren: {hostname}.{self.dns_zone} -> {ip}")
                if not self.technitium.update_record(self.dns_zone, hostname, 'A', ip):
                    errors += 1
            
            for hostname in to_delete:
                if hostname in ('@', 'ns', 'www', 'mail'):
                    continue
                log.info(f"Löschen: {hostname}.{self.dns_zone}")
                if not self.technitium.delete_record(self.dns_zone, hostname, 'A'):
                    errors += 1
            
            log.info(f"Sync complete: +{len(to_add)} ~{len(to_update)} -{len(to_delete)}" + (f" ({errors} Fehler)" if errors else ""))
            
            with sync_state._lock:
                sync_state.last_sync = datetime.now(timezone.utc).isoformat()
                sync_state.last_sync_success = errors == 0
                sync_state.sync_count += 1
                sync_state.error_count += errors
                if errors:
                    sync_state.last_error = f"{errors} Records fehlgeschlagen"
                else:
                    sync_state.last_error = None
                sync_state.records_added = len(to_add)
                sync_state.records_updated = len(to_update)
                sync_state.records_deleted = len(to_delete)
                sync_state.total_records = len(entries)
                sync_state.current_entries = sorted(
                    [{'hostname': e.hostname, 'ip': e.ip, 'fqdn': f"{e.hostname}.{self.dns_zone}"} for e in entries],
                    key=lambda x: x['hostname']
                )
            
            return errors == 0
            
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
    from flask import Flask, jsonify, Response, send_file
    
    app = Flask(__name__)
    
    flask_log = logging.getLogger('werkzeug')
    flask_log.setLevel(logging.WARNING)
    
    DASHBOARD_HTML = get_dashboard_html()
    LOGO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'opnsensetechnitiumdnssync.png')
    
    @app.route('/')
    def index():
        return Response(DASHBOARD_HTML, mimetype='text/html')
    
    @app.route('/logo.png')
    def logo():
        if os.path.isfile(LOGO_PATH):
            return send_file(LOGO_PATH, mimetype='image/png')
        return Response(status=404)
    
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
    <title>DNS Sync Dashboard</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔄</text></svg>">
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        brand: { 50: '#eff6ff', 100: '#dbeafe', 400: '#60a5fa', 500: '#3b82f6', 600: '#2563eb', 700: '#1d4ed8', 900: '#1e3a5f' }
                    }
                }
            }
        }
    </script>
    <style>
        body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }
        .log-line { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.7rem; line-height: 1.5; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0f172a; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #475569; }
        .sort-header { cursor: pointer; user-select: none; }
        .sort-header:hover { color: #e2e8f0; }
        .sort-header::after { content: ' ↕'; opacity: 0.3; font-size: 0.65rem; }
        .sort-header.asc::after { content: ' ↑'; opacity: 0.8; }
        .sort-header.desc::after { content: ' ↓'; opacity: 0.8; }
        .pulse-dot { animation: pulse-dot 2s ease-in-out infinite; }
        @keyframes pulse-dot { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
    </style>
</head>
<body class="dark bg-slate-950 text-slate-200 min-h-screen">
    <div class="max-w-7xl mx-auto px-4 py-6">

        <!-- Header -->
        <div class="flex items-center justify-between mb-6">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-lg flex items-center justify-center shrink-0 overflow-hidden" id="logo-container">
                    <img src="/logo.png" alt="Logo" class="w-10 h-10 object-contain" onerror="this.parentElement.classList.add('bg-brand-600');this.outerHTML='<svg class=&quot;w-6 h-6 text-white&quot; fill=&quot;none&quot; stroke=&quot;currentColor&quot; viewBox=&quot;0 0 24 24&quot;><path stroke-linecap=&quot;round&quot; stroke-linejoin=&quot;round&quot; stroke-width=&quot;2&quot; d=&quot;M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15&quot;/></svg>';">
                </div>
                <div>
                    <h1 class="text-xl font-bold text-white">DNS Sync Dashboard</h1>
                    <p class="text-xs text-slate-500">OPNsense &rarr; Technitium DNS</p>
                </div>
            </div>
            <div class="flex items-center gap-4">
                <span id="status-badge" class="px-3 py-1 rounded-full text-xs font-medium bg-slate-700 text-slate-300">Loading...</span>
                <div class="text-right hidden sm:block">
                    <div class="text-[10px] text-slate-600">Uptime: <span id="uptime" class="text-slate-400">-</span></div>
                    <div class="text-[10px] text-slate-600">Refresh in <span id="countdown" class="text-slate-400">-</span>s</div>
                </div>
            </div>
        </div>

        <!-- Error Banner (hidden by default) -->
        <div id="error-banner" class="hidden mb-4 bg-red-950/60 border border-red-900/50 rounded-xl px-4 py-3 flex items-start gap-3">
            <svg class="w-5 h-5 text-red-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/>
            </svg>
            <div class="flex-1 min-w-0">
                <p class="text-sm font-medium text-red-400">Last sync failed</p>
                <p class="text-xs text-red-400/70 mt-0.5 break-all" id="error-message"></p>
            </div>
        </div>

        <!-- Connection Banner (hidden if disconnected) -->
        <div id="connection-error" class="hidden mb-4 bg-amber-950/60 border border-amber-900/50 rounded-xl px-4 py-3 flex items-center gap-3">
            <svg class="w-5 h-5 text-amber-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 5.636a9 9 0 11-12.728 0M12 9v4m0 4h.01"/>
            </svg>
            <p class="text-sm text-amber-400">Dashboard can't reach the API. Is the sync service running?</p>
        </div>

        <!-- Stats Cards -->
        <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-5">
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <p class="text-[10px] text-slate-500 uppercase tracking-wider">Records</p>
                <p class="text-2xl font-bold text-white mt-1" id="total-records">-</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <p class="text-[10px] text-slate-500 uppercase tracking-wider">Added</p>
                <p class="text-2xl font-bold text-emerald-400 mt-1" id="records-added">-</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <p class="text-[10px] text-slate-500 uppercase tracking-wider">Updated</p>
                <p class="text-2xl font-bold text-amber-400 mt-1" id="records-updated">-</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <p class="text-[10px] text-slate-500 uppercase tracking-wider">Deleted</p>
                <p class="text-2xl font-bold text-red-400 mt-1" id="records-deleted">-</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <p class="text-[10px] text-slate-500 uppercase tracking-wider">Syncs</p>
                <p class="text-2xl font-bold text-brand-400 mt-1" id="sync-count">-</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <p class="text-[10px] text-slate-500 uppercase tracking-wider">Errors</p>
                <p class="text-2xl font-bold text-red-400 mt-1" id="error-count">-</p>
            </div>
        </div>

        <!-- Info Bar -->
        <div class="bg-slate-900/50 border border-slate-800 rounded-xl px-4 py-3 mb-5 flex flex-wrap gap-x-6 gap-y-2 text-xs">
            <div><span class="text-slate-500">Zone</span> <span class="text-white font-mono ml-1" id="dns-zone">-</span></div>
            <div><span class="text-slate-500">DHCP</span> <span class="text-white ml-1" id="dhcp-source">-</span></div>
            <div><span class="text-slate-500">Interval</span> <span class="text-white ml-1" id="sync-interval">-</span></div>
            <div><span class="text-slate-500">Last Sync</span> <span class="text-white ml-1" id="last-sync">-</span></div>
            <div><span class="text-slate-500">Next Sync</span> <span class="text-white ml-1" id="next-sync">-</span></div>
            <div class="hidden sm:block"><span class="text-slate-500">OPNsense</span> <span class="text-slate-400 font-mono ml-1" id="opnsense-url">-</span></div>
            <div class="hidden sm:block"><span class="text-slate-500">Technitium</span> <span class="text-slate-400 font-mono ml-1" id="technitium-url">-</span></div>
        </div>

        <!-- Main: Records + Logs -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-5">

            <!-- DNS Records -->
            <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col" style="max-height:600px">
                <div class="px-4 py-3 border-b border-slate-800 flex items-center justify-between shrink-0">
                    <h2 class="text-sm font-semibold text-white">DNS Records</h2>
                    <div class="flex items-center gap-2">
                        <input type="text" id="search-records" placeholder="Filter..."
                            class="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-brand-500 w-36">
                        <span class="text-[10px] text-slate-500 whitespace-nowrap" id="records-count">0</span>
                    </div>
                </div>
                <div class="overflow-y-auto flex-1">
                    <table class="w-full text-xs">
                        <thead class="bg-slate-800/60 sticky top-0">
                            <tr>
                                <th class="text-left px-4 py-2 text-[10px] text-slate-400 font-medium sort-header" data-sort="hostname">Hostname</th>
                                <th class="text-left px-4 py-2 text-[10px] text-slate-400 font-medium sort-header" data-sort="ip">IP</th>
                                <th class="text-left px-4 py-2 text-[10px] text-slate-400 font-medium sort-header hidden sm:table-cell" data-sort="fqdn">FQDN</th>
                            </tr>
                        </thead>
                        <tbody id="records-table" class="divide-y divide-slate-800/30">
                            <tr><td colspan="3" class="px-4 py-10 text-center text-slate-600 text-xs">Waiting for first sync...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Logs -->
            <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden flex flex-col" style="max-height:600px">
                <div class="px-4 py-3 border-b border-slate-800 flex items-center justify-between shrink-0">
                    <h2 class="text-sm font-semibold text-white">Logs</h2>
                    <div class="flex items-center gap-2">
                        <select id="log-filter" class="bg-slate-800 border border-slate-700 rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none">
                            <option value="all">All levels</option>
                            <option value="ERROR">Errors</option>
                            <option value="WARNING">Warnings</option>
                            <option value="INFO">Info</option>
                            <option value="DEBUG">Debug</option>
                        </select>
                        <button id="logs-scroll-btn" title="Scroll to top" class="text-slate-600 hover:text-slate-300 p-1">
                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"/></svg>
                        </button>
                    </div>
                </div>
                <div class="overflow-y-auto flex-1 p-1.5" id="logs-container">
                    <p class="text-slate-600 text-xs p-2">Waiting for logs...</p>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div class="mt-6 text-center text-[11px] text-slate-600">
            OPNsense Technitium DNS Sync &middot;
            <a href="https://github.com/RiDDiX/opnsense-technitium-sync" target="_blank" class="text-slate-500 hover:text-brand-400">GitHub</a>
            &middot;
            <a href="https://www.paypal.me/RiDDiX93" target="_blank" class="text-slate-500 hover:text-brand-400">&#9749; Buy me a coffee</a>
        </div>
    </div>

    <script>
        const REFRESH_MS = 15000;
        let searchFilter = '';
        let logFilter = 'all';
        let lastEntries = [];
        let lastLogs = [];
        let sortCol = 'hostname';
        let sortDir = 'asc';
        let countdownSec = REFRESH_MS / 1000;
        let connected = true;
        let uptimeStart = null;

        // event listeners
        document.getElementById('search-records').addEventListener('input', e => {
            searchFilter = e.target.value.toLowerCase();
            renderRecords(lastEntries);
        });
        document.getElementById('log-filter').addEventListener('change', e => {
            logFilter = e.target.value;
            renderLogs(lastLogs);
        });
        document.getElementById('logs-scroll-btn').addEventListener('click', () => {
            document.getElementById('logs-container').scrollTop = 0;
        });
        document.querySelectorAll('.sort-header').forEach(th => {
            th.addEventListener('click', () => {
                const col = th.dataset.sort;
                if (sortCol === col) {
                    sortDir = sortDir === 'asc' ? 'desc' : 'asc';
                } else {
                    sortCol = col;
                    sortDir = 'asc';
                }
                document.querySelectorAll('.sort-header').forEach(h => h.classList.remove('asc', 'desc'));
                th.classList.add(sortDir);
                renderRecords(lastEntries);
            });
        });
        // mark default sort header
        document.querySelector('[data-sort="hostname"]').classList.add('asc');

        function formatTime(isoStr) {
            if (!isoStr) return '-';
            const d = new Date(isoStr);
            if (isNaN(d.getTime())) return '-';
            return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }

        function formatDateTime(isoStr) {
            if (!isoStr) return '-';
            const d = new Date(isoStr);
            if (isNaN(d.getTime())) return '-';
            return d.toLocaleString([], { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }

        function formatUptime(isoStr) {
            if (!isoStr) return '-';
            const start = new Date(isoStr);
            if (isNaN(start.getTime())) return '-';
            let sec = Math.floor((Date.now() - start.getTime()) / 1000);
            if (sec < 0) sec = 0;
            const d = Math.floor(sec / 86400);
            const h = Math.floor((sec % 86400) / 3600);
            const m = Math.floor((sec % 3600) / 60);
            if (d > 0) return d + 'd ' + h + 'h';
            if (h > 0) return h + 'h ' + m + 'm';
            return m + 'm';
        }

        function sortEntries(entries) {
            return [...entries].sort((a, b) => {
                let va = (a[sortCol] || '').toLowerCase();
                let vb = (b[sortCol] || '').toLowerCase();
                if (sortCol === 'ip') {
                    // numeric IP sort
                    const na = va.split('.').map(Number);
                    const nb = vb.split('.').map(Number);
                    for (let i = 0; i < 4; i++) {
                        if ((na[i]||0) !== (nb[i]||0)) return sortDir === 'asc' ? (na[i]||0) - (nb[i]||0) : (nb[i]||0) - (na[i]||0);
                    }
                    return 0;
                }
                if (va < vb) return sortDir === 'asc' ? -1 : 1;
                if (va > vb) return sortDir === 'asc' ? 1 : -1;
                return 0;
            });
        }

        function esc(str) {
            const el = document.createElement('span');
            el.textContent = str;
            return el.innerHTML;
        }

        function renderRecords(entries) {
            lastEntries = entries;
            const tbody = document.getElementById('records-table');
            const filtered = entries.filter(e =>
                !searchFilter ||
                e.hostname.toLowerCase().includes(searchFilter) ||
                e.ip.includes(searchFilter) ||
                (e.fqdn && e.fqdn.toLowerCase().includes(searchFilter))
            );
            const sorted = sortEntries(filtered);
            document.getElementById('records-count').textContent = filtered.length + (filtered.length !== entries.length ? '/' + entries.length : '');

            if (sorted.length === 0) {
                tbody.innerHTML = entries.length === 0
                    ? '<tr><td colspan="3" class="px-4 py-10 text-center text-slate-600 text-xs">No records synced yet</td></tr>'
                    : '<tr><td colspan="3" class="px-4 py-10 text-center text-slate-600 text-xs">No records match filter</td></tr>';
                return;
            }
            tbody.innerHTML = sorted.map(e => `
                <tr class="hover:bg-slate-800/40 transition-colors">
                    <td class="px-4 py-1.5 font-mono text-emerald-400">${esc(e.hostname)}</td>
                    <td class="px-4 py-1.5 font-mono text-slate-300">${esc(e.ip)}</td>
                    <td class="px-4 py-1.5 font-mono text-slate-600 hidden sm:table-cell">${esc(e.fqdn || '')}</td>
                </tr>
            `).join('');
        }

        const LEVEL_BADGE = {
            'ERROR':   'bg-red-900/50 text-red-400 border border-red-900/30',
            'WARNING': 'bg-amber-900/40 text-amber-400 border border-amber-900/30',
            'INFO':    'bg-slate-800/80 text-slate-400 border border-slate-700/50',
            'DEBUG':   'bg-slate-800/40 text-slate-600 border border-slate-800/50',
        };

        function renderLogs(logs) {
            lastLogs = logs;
            const container = document.getElementById('logs-container');
            const filtered = logFilter === 'all' ? logs : logs.filter(l => l.level === logFilter);

            if (filtered.length === 0) {
                container.innerHTML = '<p class="text-slate-600 text-xs p-3">No logs' + (logFilter !== 'all' ? ' matching filter' : '') + '</p>';
                return;
            }
            container.innerHTML = filtered.map(l => {
                const badge = LEVEL_BADGE[l.level] || LEVEL_BADGE['INFO'];
                const ts = l.time ? l.time.split(' - ')[0].split(',')[0].split(' ').pop() || '' : '';
                return `<div class="log-line flex items-start gap-2 px-2 py-0.5 rounded hover:bg-slate-800/40">
                    <span class="shrink-0 text-[9px] text-slate-600 font-mono w-16 text-right pt-0.5">${esc(ts)}</span>
                    <span class="shrink-0 px-1.5 py-0 rounded text-[9px] font-medium ${badge}">${l.level.slice(0,4)}</span>
                    <span class="break-all text-slate-300">${esc(l.message)}</span>
                </div>`;
            }).join('');
        }

        function updateBadge(status) {
            const badge = document.getElementById('status-badge');
            if (!status.last_sync) {
                badge.textContent = 'Waiting...';
                badge.className = 'px-3 py-1 rounded-full text-xs font-medium bg-slate-700 text-slate-300';
            } else if (status.last_sync_success) {
                badge.innerHTML = '<span class="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5 pulse-dot"></span>Healthy';
                badge.className = 'px-3 py-1 rounded-full text-xs font-medium bg-emerald-900/40 text-emerald-400 border border-emerald-800/50 flex items-center';
            } else {
                badge.innerHTML = '<span class="inline-block w-1.5 h-1.5 rounded-full bg-red-400 mr-1.5"></span>Error';
                badge.className = 'px-3 py-1 rounded-full text-xs font-medium bg-red-900/40 text-red-400 border border-red-800/50 flex items-center';
            }
        }

        function updateErrorBanner(status) {
            const banner = document.getElementById('error-banner');
            if (status.last_error && !status.last_sync_success) {
                document.getElementById('error-message').textContent = status.last_error;
                banner.classList.remove('hidden');
            } else {
                banner.classList.add('hidden');
            }
        }

        async function refresh() {
            try {
                const [statusRes, logsRes] = await Promise.all([
                    fetch('/api/status'),
                    fetch('/api/logs')
                ]);
                if (!statusRes.ok || !logsRes.ok) throw new Error('API returned ' + statusRes.status);

                const status = await statusRes.json();
                const logs = await logsRes.json();

                // connection ok
                if (!connected) {
                    connected = true;
                    document.getElementById('connection-error').classList.add('hidden');
                }

                // stats
                document.getElementById('total-records').textContent = status.total_records;
                document.getElementById('records-added').textContent = status.records_added > 0 ? '+' + status.records_added : '0';
                document.getElementById('records-updated').textContent = status.records_updated > 0 ? '~' + status.records_updated : '0';
                document.getElementById('records-deleted').textContent = status.records_deleted > 0 ? '-' + status.records_deleted : '0';
                document.getElementById('sync-count').textContent = status.sync_count;
                document.getElementById('error-count').textContent = status.error_count;

                // info bar
                document.getElementById('dns-zone').textContent = status.dns_zone || '-';
                document.getElementById('dhcp-source').textContent = status.dhcp_source || '-';
                document.getElementById('sync-interval').textContent = (status.sync_interval || '-') + ' min';
                document.getElementById('last-sync').textContent = formatDateTime(status.last_sync);
                document.getElementById('next-sync').textContent = formatDateTime(status.next_sync);
                document.getElementById('opnsense-url').textContent = status.opnsense_url || '-';
                document.getElementById('technitium-url').textContent = status.technitium_url || '-';
                uptimeStart = status.uptime_start;
                document.getElementById('uptime').textContent = formatUptime(uptimeStart);

                updateBadge(status);
                updateErrorBanner(status);
                renderRecords(status.current_entries || []);
                renderLogs(logs || []);
            } catch (err) {
                console.error('Refresh error:', err);
                connected = false;
                document.getElementById('connection-error').classList.remove('hidden');
            }
            countdownSec = REFRESH_MS / 1000;
        }

        setInterval(() => {
            countdownSec = Math.max(0, countdownSec - 1);
            document.getElementById('countdown').textContent = countdownSec;
            if (uptimeStart) document.getElementById('uptime').textContent = formatUptime(uptimeStart);
        }, 1000);

        refresh();
        setInterval(refresh, REFRESH_MS);
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
