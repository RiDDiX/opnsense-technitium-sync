#!/usr/bin/env python3
"""
OPNsense to TechnitiumDNS Sync
Synchronisiert DHCP-Leases/Hostnamen von OPNsense zu TechnitiumDNS
"""

import os
import sys
import time
import json
import logging
import argparse
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import requests
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class DnsEntry:
    hostname: str
    ip: str
    zone: str
    
    @property
    def fqdn(self) -> str:
        return f"{self.hostname}.{self.zone}"


class OPNsenseAPI:
    """OPNsense API Client"""
    
    # Standard OPNsense Search-Body
    SEARCH_BODY = {"current": 1, "rowCount": -1, "searchPhrase": "", "sort": {}}
    
    def __init__(self, url: str, api_key: str, api_secret: str, verify_ssl: bool = False):
        self.base_url = url.rstrip('/')
        self.api_key = api_key
        self.api_secret = api_secret
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.auth = (api_key, api_secret)
    
    def _get(self, path: str) -> Optional[Dict]:
        """GET Request"""
        url = f"{self.base_url}{path}"
        try:
            response = self.session.get(url, verify=self.verify_ssl, timeout=30)
            logger.debug(f"GET {path} -> {response.status_code}")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            logger.debug(f"GET {path} -> {e.response.status_code}")
            return None
        except Exception as e:
            logger.debug(f"GET {path} -> Fehler: {e}")
            return None
    
    def _post_search(self, path: str) -> Optional[Dict]:
        """POST Search Request (OPNsense grid/search Endpunkte)"""
        url = f"{self.base_url}{path}"
        try:
            response = self.session.post(
                url, json=self.SEARCH_BODY, verify=self.verify_ssl, timeout=30
            )
            logger.debug(f"POST {path} -> {response.status_code}")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            logger.debug(f"POST {path} -> {e.response.status_code}")
            return None
        except Exception as e:
            logger.debug(f"POST {path} -> Fehler: {e}")
            return None
    
    def _try_endpoint(self, path: str) -> Optional[Dict]:
        """Versucht GET, dann POST für einen Endpunkt"""
        data = self._get(path)
        if data is not None:
            return data
        data = self._post_search(path)
        return data
    
    def discover_endpoints(self):
        """Testet alle bekannten DHCP-API-Endpunkte und gibt Ergebnisse aus"""
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
        
        logger.info("=== API Endpoint Discovery ===")
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
                logger.info(f"  {symbol} {method:4s} {path} -> {status}{body_preview}")
                
            except Exception as e:
                logger.info(f"  ✗ {method:4s} {path} -> Fehler: {e}")
        
        logger.info("=== Discovery Ende ===")
    
    def get_dhcp_leases(self) -> List[DnsEntry]:
        """Holt DHCP Leases von OPNsense (KEA, Dnsmasq oder ISC)"""
        # 1. KEA Leases (POST)
        entries = self._get_kea_leases()
        if entries:
            return entries
        
        # 2. Dnsmasq Leases
        entries = self._get_dnsmasq_leases()
        if entries:
            return entries
        
        # 3. ISC DHCP (legacy)
        entries = self._get_isc_leases()
        if entries:
            return entries
        
        logger.warning("Keine DHCP-Leases gefunden (KEA/Dnsmasq/ISC)")
        return []
    
    def _get_kea_leases(self) -> List[DnsEntry]:
        """Holt KEA DHCP Leases über /api/kea/leases/search"""
        data = self._try_endpoint("/api/kea/leases/search")
        if data is None:
            return []
        
        rows = self._extract_rows(data)
        if rows:
            logger.debug(f"KEA leases: {len(rows)} rows, sample: {json.dumps(rows[0], indent=2)}")
        
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
            logger.info(f"KEA Leases: {len(entries)} Einträge")
        return entries
    
    def _get_dnsmasq_leases(self) -> List[DnsEntry]:
        """Holt Dnsmasq DHCP Leases über /api/dnsmasq/leases/searchLease"""
        data = self._try_endpoint("/api/dnsmasq/leases/searchLease")
        if data is None:
            return []
        
        rows = self._extract_rows(data)
        if rows:
            logger.debug(f"Dnsmasq leases: {len(rows)} rows, sample: {json.dumps(rows[0], indent=2)}")
        
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
            logger.info(f"Dnsmasq Leases: {len(entries)} Einträge")
        return entries
    
    def _get_isc_leases(self) -> List[DnsEntry]:
        """Holt ISC DHCP Leases (legacy)"""
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
            logger.info(f"ISC Leases: {len(entries)} Einträge")
        return entries
    
    def get_static_mappings(self) -> List[DnsEntry]:
        """Holt statische DHCP Mappings (KEA Reservations + Unbound Host Overrides)"""
        entries = []
        
        kea = self._get_kea_reservations()
        entries.extend(kea)
        
        unbound = self._get_unbound_host_overrides()
        entries.extend(unbound)
        
        if entries:
            logger.info(f"Statische Mappings: {len(entries)} gefunden")
        return entries
    
    def _get_kea_reservations(self) -> List[DnsEntry]:
        """Holt KEA DHCP reservations über /api/kea/dhcpv4/search_reservation (POST)"""
        data = self._post_search("/api/kea/dhcpv4/search_reservation")
        if data is None:
            return []
        
        rows = self._extract_rows(data)
        if rows:
            logger.debug(f"KEA reservations: {len(rows)} rows, sample: {json.dumps(rows[0], indent=2)}")
        
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
            logger.info(f"KEA Reservations: {len(entries)} Einträge")
        return entries
    
    def _get_unbound_host_overrides(self) -> List[DnsEntry]:
        """Holt Unbound DNS Host Overrides über /api/unbound/settings/searchHostOverride"""
        data = self._try_endpoint("/api/unbound/settings/searchHostOverride")
        if data is None:
            return []
        
        rows = self._extract_rows(data)
        if rows:
            logger.debug(f"Unbound overrides: {len(rows)} rows, sample: {json.dumps(rows[0], indent=2)}")
        
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
            logger.info(f"Unbound Host Overrides: {len(entries)} Einträge")
        return entries
    
    @staticmethod
    def _extract_rows(data: Dict) -> List[Dict]:
        """Extrahiert rows/leases aus OPNsense API Response"""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get('rows', []) or data.get('leases', []) or []
        return []
    
    @staticmethod
    def _extract_field(row: Dict, keys: List[str]) -> str:
        """Extrahiert erstes nicht-leeres Feld aus einer Liste von Keys"""
        for key in keys:
            val = row.get(key, '')
            if val:
                return str(val).strip().lower()
        return ''
    
    @staticmethod
    def _sanitize_hostname(hostname: str) -> str:
        """Bereinigt Hostname für DNS-Kompatibilität"""
        # Erlaubte Zeichen: a-z, 0-9, -
        sanitized = ''.join(
            c if c.isalnum() or c == '-' else '-' 
            for c in hostname
        )
        # Entferne führende/nachfolgende Bindestriche
        sanitized = sanitized.strip('-')
        # Max 63 Zeichen für DNS Labels
        return sanitized[:63]


class TechnitiumAPI:
    """Technitium DNS API Client"""
    
    def __init__(self, url: str, token: str):
        self.base_url = url.rstrip('/')
        self.token = token
        self.session = requests.Session()
    
    def _api_call(self, path: str, params: Optional[Dict] = None) -> Dict:
        """Führt API Call aus"""
        url = f"{self.base_url}/api{path}"
        
        if params is None:
            params = {}
        params['token'] = self.token
        
        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Technitium API Fehler: {e}")
            return {'status': 'error', 'errorMessage': str(e)}
    
    def list_zones(self) -> List[Dict]:
        """Listet alle Zonen"""
        result = self._api_call('/zones/list')
        return result.get('response', {}).get('zones', [])
    
    def zone_exists(self, zone_name: str) -> bool:
        """Prüft ob Zone existiert"""
        zones = self.list_zones()
        return any(z.get('name') == zone_name for z in zones)
    
    def create_zone(self, zone_name: str) -> bool:
        """Erstellt neue Zone"""
        params = {
            'zone': zone_name,
            'type': 'Primary'
        }
        result = self._api_call('/zones/create', params)
        
        if result.get('status') == 'ok':
            logger.info(f"Zone {zone_name} erstellt")
            return True
        else:
            logger.error(f"Konnte Zone nicht erstellen: {result}")
            return False
    
    def get_records(self, zone_name: str) -> List[Dict]:
        """Holt alle Records einer Zone"""
        params = {'zone': zone_name}
        result = self._api_call('/zones/records', params)
        
        if result.get('status') == 'ok':
            return result.get('response', {}).get('records', [])
        return []
    
    def get_a_records(self, zone_name: str) -> Dict[str, str]:
        """Holt alle A-Records als Dict {hostname: ip}"""
        records = self.get_records(zone_name)
        a_records = {}
        
        for record in records:
            if record.get('type') == 'A':
                name = record.get('name', '').lower()
                ip = record.get('value', '')
                # Entferne Zone-Suffix für Vergleich
                short_name = name.replace(f'.{zone_name}', '').replace(zone_name, '')
                a_records[short_name] = ip
        
        return a_records
    
    def add_record(self, zone_name: str, name: str, record_type: str, value: str, ttl: int = 300) -> bool:
        """Fügt Record hinzu"""
        # Technitium erwartet FQDN als domain: hostname.zone
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
            logger.debug(f"Record hinzugefügt: {name}.{zone_name} -> {value}")
            return True
        else:
            logger.error(f"Konnte Record nicht hinzufügen: {result}")
            return False
    
    def delete_record(self, zone_name: str, name: str, record_type: str, value: Optional[str] = None) -> bool:
        """Löscht Record"""
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
            logger.debug(f"Record gelöscht: {name}.{zone_name}")
            return True
        else:
            logger.error(f"Konnte Record nicht löschen: {result}")
            return False
    
    def update_record(self, zone_name: str, name: str, record_type: str, new_value: str, ttl: int = 300) -> bool:
        """Aktualisiert Record (löscht alten, fügt neuen hinzu)"""
        # Lösche alten Record
        self.delete_record(zone_name, name, record_type)
        # Füge neuen hinzu
        return self.add_record(zone_name, name, record_type, new_value, ttl)


class DNSSync:
    """Haupt-Synchronisationsklasse"""
    
    def __init__(self):
        # OPNsense Config
        self.opnsense_url = os.getenv('OPNSENSE_URL', 'https://opnsense.home.arpa')
        self.opnsense_key = os.getenv('OPNSENSE_API_KEY', '')
        self.opnsense_secret = os.getenv('OPNSENSE_API_SECRET', '')
        self.opnsense_verify_ssl = os.getenv('OPNSENSE_VERIFY_SSL', 'false').lower() == 'true'
        
        # Technitium Config
        self.technitium_url = os.getenv('TECHNITIUM_URL', 'http://technitium.home.arpa:5380')
        self.technitium_token = os.getenv('TECHNITIUM_TOKEN', '')
        
        # Sync Config
        self.dns_zone = os.getenv('DNS_ZONE', 'home.arpa')
        self.sync_interval = int(os.getenv('SYNC_INTERVAL_MINUTES', '5'))
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
        
        # Statische Einträge (hostname=ip,hostname2=ip2)
        self.static_entries_str = os.getenv('STATIC_ENTRIES', '')
        
        # Setze Log-Level
        logging.getLogger().setLevel(getattr(logging, self.log_level.upper()))
        
        # Clients
        self.opnsense: Optional[OPNsenseAPI] = None
        self.technitium: Optional[TechnitiumAPI] = None
    
    def validate_config(self) -> bool:
        """Validiert Konfiguration"""
        if not self.opnsense_key or not self.opnsense_secret:
            logger.error("OPNSENSE_API_KEY und OPNSENSE_API_SECRET müssen gesetzt sein")
            return False
        
        if not self.technitium_token:
            logger.error("TECHNITIUM_TOKEN muss gesetzt sein")
            return False
        
        return True
    
    def initialize(self):
        """Initialisiert API Clients"""
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
        """Parst statische Einträge aus Umgebungsvariable"""
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
        """Führt Synchronisation durch"""
        logger.info(f"=== Sync Start === Zone: {self.dns_zone}")
        
        try:
            # 1. Hole Daten von OPNsense
            dhcp_entries = self.opnsense.get_dhcp_leases()
            static_mappings = self.opnsense.get_static_mappings()
            manual_entries = self.parse_static_entries()
            
            # Kombiniere alle Einträge (duplikate nach IP entfernen)
            all_entries = {}
            for entry in dhcp_entries + static_mappings + manual_entries:
                all_entries[entry.hostname] = entry
            
            entries = list(all_entries.values())
            logger.info(f"Gesamt: {len(entries)} eindeutige Einträge")
            
            if not entries:
                logger.warning("Keine Einträge zu synchronisieren")
                return True
            
            # 2. Prüfe/Erstelle Zone in Technitium
            if not self.technitium.zone_exists(self.dns_zone):
                logger.info(f"Zone {self.dns_zone} existiert nicht, erstelle...")
                if not self.technitium.create_zone(self.dns_zone):
                    return False
            
            # 3. Hole aktuelle Records
            current_records = self.technitium.get_a_records(self.dns_zone)
            logger.info(f"Technitium: {len(current_records)} existierende A-Records")
            
            # 4. Berechne Änderungen
            desired_records = {e.hostname: e.ip for e in entries}
            
            to_add = []
            to_update = []
            to_delete = []
            
            # Was hinzufügen/aktualisieren?
            for hostname, ip in desired_records.items():
                if hostname not in current_records:
                    to_add.append((hostname, ip))
                elif current_records[hostname] != ip:
                    to_update.append((hostname, ip))
            
            # Was löschen? (nur wenn es aus OPNsense kam)
            opnsense_hostnames = set(desired_records.keys())
            for hostname in current_records:
                if hostname not in opnsense_hostnames:
                    # Prüfe ob es ein manueller Eintrag war
                    if hostname not in {e.hostname for e in manual_entries}:
                        to_delete.append(hostname)
            
            # 5. Führe Änderungen durch
            for hostname, ip in to_add:
                logger.info(f"Hinzufügen: {hostname}.{self.dns_zone} -> {ip}")
                self.technitium.add_record(self.dns_zone, hostname, 'A', ip)
            
            for hostname, ip in to_update:
                logger.info(f"Aktualisieren: {hostname}.{self.dns_zone} -> {ip}")
                self.technitium.update_record(self.dns_zone, hostname, 'A', ip)
            
            for hostname in to_delete:
                # Nur löschen wenn es keine wichtigen System-Records sind
                if hostname not in ['@', 'ns', 'www', 'mail']:
                    logger.info(f"Löschen: {hostname}.{self.dns_zone}")
                    self.technitium.delete_record(self.dns_zone, hostname, 'A')
            
            logger.info(f"Sync complete: +{len(to_add)} ~{len(to_update)} -{len(to_delete)}")
            return True
            
        except Exception as e:
            logger.exception(f"Sync fehlgeschlagen: {e}")
            return False
    
    def run(self, once: bool = False, discover: bool = False):
        """Hauptschleife"""
        if not self.validate_config():
            sys.exit(1)
        
        self.initialize()
        
        if discover:
            logging.getLogger().setLevel(logging.DEBUG)
            self.opnsense.discover_endpoints()
            sys.exit(0)
        
        if once:
            logger.info("Einmalige Synchronisation...")
            success = self.sync()
            sys.exit(0 if success else 1)
        
        logger.info(f"DNS Sync gestartet - Intervall: {self.sync_interval} Minuten")
        
        while True:
            success = self.sync()
            
            if success:
                logger.info(f"Nächster Sync in {self.sync_interval} Minuten...")
            else:
                logger.warning("Sync fehlgeschlagen, retry in 1 Minute...")
                time.sleep(60)
                continue
            
            # Warte auf nächsten Sync
            time.sleep(self.sync_interval * 60)


def main():
    parser = argparse.ArgumentParser(description='OPNsense zu TechnitiumDNS Sync')
    parser.add_argument('--once', action='store_true', help='Einmalige Synchronisation')
    parser.add_argument('--discover', action='store_true', help='Teste alle bekannten API-Endpunkte')
    args = parser.parse_args()
    
    sync = DNSSync()
    sync.run(once=args.once, discover=args.discover)


if __name__ == '__main__':
    main()
