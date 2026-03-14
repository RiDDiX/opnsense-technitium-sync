#!/usr/bin/env python3

import unittest
from unittest.mock import patch
from sync import TechnitiumAPI, OPNsenseAPI, DNSSync, DnsEntry, MANAGED_COMMENT


class TestTechnitiumDeleteRecord(unittest.TestCase):
    """Verify delete_record sends ipAddress param for A records (root cause fix)."""

    def setUp(self):
        self.api = TechnitiumAPI('http://localhost:5380', 'test-token')

    @patch.object(TechnitiumAPI, '_api_call')
    def test_delete_a_record_sends_ipaddress(self, mock_call):
        mock_call.return_value = {'status': 'ok'}
        self.api.delete_record('home.arpa', 'printer', 'A', '192.168.1.50')
        mock_call.assert_called_once_with('/zones/records/delete', {
            'zone': 'home.arpa',
            'domain': 'printer.home.arpa',
            'type': 'A',
            'ipAddress': '192.168.1.50',
        })

    @patch.object(TechnitiumAPI, '_api_call')
    def test_delete_a_record_without_ip_no_ipaddress_param(self, mock_call):
        mock_call.return_value = {'status': 'ok'}
        self.api.delete_record('home.arpa', 'printer', 'A')
        mock_call.assert_called_once_with('/zones/records/delete', {
            'zone': 'home.arpa',
            'domain': 'printer.home.arpa',
            'type': 'A',
        })

    @patch.object(TechnitiumAPI, '_api_call')
    def test_delete_non_a_record_sends_value(self, mock_call):
        mock_call.return_value = {'status': 'ok'}
        self.api.delete_record('home.arpa', 'printer', 'TXT', 'some-text')
        mock_call.assert_called_once_with('/zones/records/delete', {
            'zone': 'home.arpa',
            'domain': 'printer.home.arpa',
            'type': 'TXT',
            'value': 'some-text',
        })


class TestTechnitiumAddRecord(unittest.TestCase):
    """Verify add_record sends ipAddress for A records and comments."""

    def setUp(self):
        self.api = TechnitiumAPI('http://localhost:5380', 'test-token')

    @patch.object(TechnitiumAPI, '_api_call')
    def test_add_a_record_sends_ipaddress(self, mock_call):
        mock_call.return_value = {'status': 'ok'}
        self.api.add_record('home.arpa', 'printer', 'A', '192.168.1.50', comments='test')
        mock_call.assert_called_once_with('/zones/records/add', {
            'zone': 'home.arpa',
            'domain': 'printer.home.arpa',
            'type': 'A',
            'ttl': 300,
            'ipAddress': '192.168.1.50',
            'comments': 'test',
        })

    @patch.object(TechnitiumAPI, '_api_call')
    def test_add_non_a_record_sends_value(self, mock_call):
        mock_call.return_value = {'status': 'ok'}
        self.api.add_record('home.arpa', 'printer', 'TXT', 'some-text')
        mock_call.assert_called_once_with('/zones/records/add', {
            'zone': 'home.arpa',
            'domain': 'printer.home.arpa',
            'type': 'TXT',
            'ttl': 300,
            'value': 'some-text',
        })


class TestTechnitiumUpdateRecord(unittest.TestCase):
    """Verify update_record uses native update API with ipAddress/newIpAddress."""

    def setUp(self):
        self.api = TechnitiumAPI('http://localhost:5380', 'test-token')

    @patch.object(TechnitiumAPI, '_api_call')
    def test_update_a_record_native_api(self, mock_call):
        mock_call.return_value = {'status': 'ok'}
        result = self.api.update_record(
            'home.arpa', 'printer', 'A', '192.168.1.51',
            old_value='192.168.1.50', comments=MANAGED_COMMENT
        )
        self.assertTrue(result)
        mock_call.assert_called_once_with('/zones/records/update', {
            'zone': 'home.arpa',
            'domain': 'printer.home.arpa',
            'type': 'A',
            'ipAddress': '192.168.1.50',
            'newIpAddress': '192.168.1.51',
            'ttl': 300,
            'comments': MANAGED_COMMENT,
        })

    @patch.object(TechnitiumAPI, '_api_call')
    def test_update_fallback_on_native_fail(self, mock_call):
        mock_call.side_effect = [
            {'status': 'error', 'errorMessage': 'fail'},
            {'status': 'ok'},
            {'status': 'ok'},
        ]
        result = self.api.update_record(
            'home.arpa', 'printer', 'A', '192.168.1.51',
            old_value='192.168.1.50', comments=MANAGED_COMMENT
        )
        self.assertTrue(result)
        self.assertEqual(mock_call.call_count, 3)


class TestGetARecords(unittest.TestCase):
    """Verify get_a_records returns dict with ip and comments."""

    def setUp(self):
        self.api = TechnitiumAPI('http://localhost:5380', 'test-token')

    @patch.object(TechnitiumAPI, 'get_records')
    def test_returns_ip_and_comments(self, mock_get):
        mock_get.return_value = [
            {
                'type': 'A',
                'name': 'printer.home.arpa',
                'rData': {'ipAddress': '192.168.1.50'},
                'comments': MANAGED_COMMENT,
            },
            {
                'type': 'A',
                'name': 'nas.home.arpa',
                'rData': {'ipAddress': '192.168.1.10'},
            },
            {
                'type': 'NS',
                'name': 'home.arpa',
                'rData': {'nameServer': 'ns1'},
            },
        ]
        result = self.api.get_a_records('home.arpa')
        self.assertEqual(result, {
            'printer': {'ip': '192.168.1.50', 'comments': MANAGED_COMMENT},
            'nas': {'ip': '192.168.1.10', 'comments': ''},
        })


class TestBombproofDeletion(unittest.TestCase):
    """Verify only managed records are deleted."""

    @patch.dict('os.environ', {
        'OPNSENSE_URL': 'https://opnsense.test',
        'OPNSENSE_API_KEY': 'key',
        'OPNSENSE_API_SECRET': 'secret',
        'TECHNITIUM_URL': 'http://technitium.test:5380',
        'TECHNITIUM_TOKEN': 'tok',
        'DNS_ZONE': 'home.arpa',
        'SYNC_INTERVAL_MINUTES': '5',
        'DASHBOARD_ENABLED': 'false',
    })
    def test_unmanaged_records_not_deleted(self):
        syncer = DNSSync()
        syncer.initialize()

        with patch.object(syncer.opnsense, 'get_dhcp_leases') as mock_dhcp, \
             patch.object(syncer.opnsense, 'get_static_mappings') as mock_static, \
             patch.object(syncer.technitium, 'zone_exists') as mock_zone_exists, \
             patch.object(syncer.technitium, 'get_a_records') as mock_get_a, \
             patch.object(syncer.technitium, 'add_record') as mock_add, \
             patch.object(syncer.technitium, 'delete_record') as mock_delete:

            mock_dhcp.return_value = [DnsEntry('laptop', '192.168.1.100', '')]
            mock_static.return_value = []
            mock_zone_exists.return_value = True
            mock_get_a.return_value = {
                'laptop': {'ip': '192.168.1.100', 'comments': MANAGED_COMMENT},
                'manual-record': {'ip': '10.0.0.1', 'comments': ''},
                'old-managed': {'ip': '192.168.1.200', 'comments': MANAGED_COMMENT},
            }
            mock_add.return_value = True
            mock_delete.return_value = True

            result = syncer.sync()
            self.assertTrue(result)

            mock_delete.assert_called_once_with('home.arpa', 'old-managed', 'A', '192.168.1.200')
            mock_add.assert_not_called()

    @patch.dict('os.environ', {
        'OPNSENSE_URL': 'https://opnsense.test',
        'OPNSENSE_API_KEY': 'key',
        'OPNSENSE_API_SECRET': 'secret',
        'TECHNITIUM_URL': 'http://technitium.test:5380',
        'TECHNITIUM_TOKEN': 'tok',
        'DNS_ZONE': 'home.arpa',
        'SYNC_INTERVAL_MINUTES': '5',
        'DASHBOARD_ENABLED': 'false',
    })
    def test_empty_fetch_skips_deletes(self):
        syncer = DNSSync()
        syncer.initialize()

        with patch.object(syncer.opnsense, 'get_dhcp_leases') as mock_dhcp, \
             patch.object(syncer.opnsense, 'get_static_mappings') as mock_static, \
             patch.object(syncer.technitium, 'zone_exists') as mock_zone_exists, \
             patch.object(syncer.technitium, 'get_a_records') as mock_get_a, \
             patch.object(syncer.technitium, 'delete_record') as mock_delete:

            mock_dhcp.return_value = []
            mock_static.return_value = []
            mock_zone_exists.return_value = True
            mock_get_a.return_value = {
                'old-record': {'ip': '192.168.1.200', 'comments': MANAGED_COMMENT},
            }

            result = syncer.sync()
            self.assertTrue(result)
            mock_delete.assert_not_called()


class TestDeleteListPreservesIP(unittest.TestCase):
    """Verify the delete call includes ipAddress from current_records."""

    @patch.dict('os.environ', {
        'OPNSENSE_URL': 'https://opnsense.test',
        'OPNSENSE_API_KEY': 'key',
        'OPNSENSE_API_SECRET': 'secret',
        'TECHNITIUM_URL': 'http://technitium.test:5380',
        'TECHNITIUM_TOKEN': 'tok',
        'DNS_ZONE': 'home.arpa',
        'SYNC_INTERVAL_MINUTES': '5',
        'DASHBOARD_ENABLED': 'false',
    })
    def test_delete_passes_ip(self):
        syncer = DNSSync()
        syncer.initialize()

        with patch.object(syncer.opnsense, 'get_dhcp_leases') as mock_dhcp, \
             patch.object(syncer.opnsense, 'get_static_mappings') as mock_static, \
             patch.object(syncer.technitium, 'zone_exists') as mock_zone_exists, \
             patch.object(syncer.technitium, 'get_a_records') as mock_get_a, \
             patch.object(syncer.technitium, 'add_record') as mock_add, \
             patch.object(syncer.technitium, 'delete_record') as mock_delete:

            mock_dhcp.return_value = [DnsEntry('keep', '192.168.1.1', '')]
            mock_static.return_value = []
            mock_zone_exists.return_value = True
            mock_get_a.return_value = {
                'keep': {'ip': '192.168.1.1', 'comments': MANAGED_COMMENT},
                'stale': {'ip': '192.168.1.99', 'comments': MANAGED_COMMENT},
            }
            mock_add.return_value = True
            mock_delete.return_value = True

            syncer.sync()

            mock_delete.assert_called_once_with('home.arpa', 'stale', 'A', '192.168.1.99')


class TestUpdatePassesOldIP(unittest.TestCase):
    """Verify update passes old_value for native update API."""

    @patch.dict('os.environ', {
        'OPNSENSE_URL': 'https://opnsense.test',
        'OPNSENSE_API_KEY': 'key',
        'OPNSENSE_API_SECRET': 'secret',
        'TECHNITIUM_URL': 'http://technitium.test:5380',
        'TECHNITIUM_TOKEN': 'tok',
        'DNS_ZONE': 'home.arpa',
        'SYNC_INTERVAL_MINUTES': '5',
        'DASHBOARD_ENABLED': 'false',
    })
    def test_update_passes_old_and_new_ip(self):
        syncer = DNSSync()
        syncer.initialize()

        with patch.object(syncer.opnsense, 'get_dhcp_leases') as mock_dhcp, \
             patch.object(syncer.opnsense, 'get_static_mappings') as mock_static, \
             patch.object(syncer.technitium, 'zone_exists') as mock_zone_exists, \
             patch.object(syncer.technitium, 'get_a_records') as mock_get_a, \
             patch.object(syncer.technitium, 'update_record') as mock_update:

            mock_dhcp.return_value = [DnsEntry('printer', '192.168.1.51', '')]
            mock_static.return_value = []
            mock_zone_exists.return_value = True
            mock_get_a.return_value = {
                'printer': {'ip': '192.168.1.50', 'comments': MANAGED_COMMENT},
            }
            mock_update.return_value = True

            syncer.sync()

            mock_update.assert_called_once_with(
                'home.arpa', 'printer', 'A', '192.168.1.51',
                old_value='192.168.1.50', comments=MANAGED_COMMENT
            )


class TestTokenMasking(unittest.TestCase):
    """Verify token is not leaked in error messages."""

    def test_api_call_masks_token_in_error(self):
        api = TechnitiumAPI('http://nonexistent.invalid:9999', 'super-secret-token')
        result = api._api_call('/zones/list', retries=1)
        self.assertEqual(result['status'], 'error')
        self.assertNotIn('super-secret-token', result['errorMessage'])


class TestDnsmasqEndpoint(unittest.TestCase):
    """Verify Dnsmasq uses corrected endpoint path."""

    def test_dnsmasq_endpoint_path(self):
        api = OPNsenseAPI('https://test', 'key', 'secret')
        with patch.object(api, '_try_endpoint', return_value=None) as mock_try:
            api._get_dnsmasq_leases()
            mock_try.assert_called_once_with('/api/dnsmasq/leases/search')


if __name__ == '__main__':
    unittest.main()
