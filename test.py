#!/usr/bin/env python3
"""Unit tests for main.py using Python's unittest.

These tests mock external commands and system tools so they run without
nmap/arp-scan/etc. present. Place this file next to main.py and run:

    python3 -m unittest -v test.py

or simply:

    python3 test.py -v
"""

import io
import json
import sys
import types
import unittest
from unittest.mock import patch

import importlib

# Ensure the module under test can be imported as 'main'
MAIN_MODULE_NAME = 'main'


class TestMainParsers(unittest.TestCase):
    def setUp(self):
        # Reload fresh in each test to avoid cross-test patch bleed
        if MAIN_MODULE_NAME in sys.modules:
            importlib.reload(sys.modules[MAIN_MODULE_NAME])
        else:
            importlib.import_module(MAIN_MODULE_NAME)
        self.main = sys.modules[MAIN_MODULE_NAME]

    def test_parse_arp_scan_output(self):
        raw = (
            "Interface: wlo1, datalink type: EN10MB (Ethernet)\n"
            "192.168.0.1\t00:11:22:33:44:55\tRouter Inc\n"
            "192.168.0.42\tAA:BB:CC:DD:EE:FF\tDevice Co\n"
            "2 packets received by filter, 0 packets dropped by kernel\n"
        )
        hosts = self.main.parse_arp_scan_output(raw)
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0]['ip'], '192.168.0.1')
        self.assertEqual(hosts[0]['mac'], '00:11:22:33:44:55')
        self.assertEqual(hosts[0]['vendor'], 'Router Inc')
        self.assertEqual(hosts[1]['ip'], '192.168.0.42')
        self.assertEqual(hosts[1]['mac'], 'AA:BB:CC:DD:EE:FF')

    def test_parse_nmap_grepable(self):
        raw = (
            "# Nmap 7.94 scan initiated\n"
            "Host: 192.168.0.10 ()\tStatus: Up\n"
            "Host: 192.168.0.11 ()\tStatus: Up\n"
            "# Nmap done\n"
        )
        ips = self.main.parse_nmap_grepable(raw)
        self.assertEqual(ips, ['192.168.0.10', '192.168.0.11'])


class TestMainHelpers(unittest.TestCase):
    def setUp(self):
        if MAIN_MODULE_NAME in sys.modules:
            importlib.reload(sys.modules[MAIN_MODULE_NAME])
        else:
            importlib.import_module(MAIN_MODULE_NAME)
        self.main = sys.modules[MAIN_MODULE_NAME]

    @patch('main.which')
    @patch('main.run')
    def test_detect_subnet_auto_via_ip(self, mock_run, mock_which):
        mock_which.return_value = '/usr/bin/ip'
        mock_run.return_value = (0, '2: wlo1    inet 192.168.0.110/24 brd 192.168.0.255 scope global', '')
        cidr = self.main.detect_subnet(auto=True, provided=None)
        self.assertEqual(cidr, '192.168.0.110/24')

    def test_detect_subnet_provided(self):
        cidr = self.main.detect_subnet(auto=False, provided='10.0.0.0/24')
        self.assertEqual(cidr, '10.0.0.0/24')

    @patch('main.which')
    @patch('main.run')
    def test_probe_ip_neigh_parsing(self, mock_run, mock_which):
        mock_which.side_effect = lambda cmd: '/usr/bin/ip' if cmd == 'ip' else None
        mock_run.return_value = (0, '192.168.0.204 dev wlo1 lladdr 00:23:57:4c:66:21 STALE', '')
        res = self.main.probe_ip_neigh('192.168.0.204')
        self.assertEqual(res['mac'].lower(), '00:23:57:4c:66:21')
        self.assertEqual(res['dev'], 'wlo1')
        self.assertEqual(res['state'], 'STALE')

    @patch('main.which')
    @patch('main.run')
    def test_resolve_mdns(self, mock_run, mock_which):
        mock_which.side_effect = lambda cmd: '/usr/bin/avahi-resolve-address' if cmd == 'avahi-resolve-address' else None
        mock_run.return_value = (0, '192.168.0.42\thostname.local', '')
        name = self.main.resolve_mdns('192.168.0.42', timeout=5)
        self.assertEqual(name, 'hostname.local')

    @patch('main.which')
    @patch('main.run')
    def test_run_nbtscan_range(self, mock_run, mock_which):
        mock_which.side_effect = lambda cmd: '/usr/bin/nbtscan' if cmd == 'nbtscan' else None
        mock_run.return_value = (0, '192.168.0.50    ALPHA<00>  UNIQUE\n192.168.0.51    BETA<00>  UNIQUE', '')
        res = self.main.run_nbtscan_range('192.168.0.0/24', timeout=10)
        self.assertEqual(res['192.168.0.50'], 'ALPHA<00>')
        self.assertEqual(res['192.168.0.51'], 'BETA<00>')


class TestAggregationAndOutput(unittest.TestCase):
    def setUp(self):
        if MAIN_MODULE_NAME in sys.modules:
            importlib.reload(sys.modules[MAIN_MODULE_NAME])
        else:
            importlib.import_module(MAIN_MODULE_NAME)
        self.main = sys.modules[MAIN_MODULE_NAME]

    @patch('main.reverse_dns')
    @patch('main.resolve_mdns')
    @patch('main.probe_ip_neigh')
    @patch('main.run_nbtscan_range')
    @patch('main.run_nmap_hosts')
    @patch('main.run_arp_scan')
    @patch('main.which')
    def test_aggregate_hosts_merges_and_sorts(self, mock_which, mock_arp, mock_nmap, mock_nbts, mock_neigh, mock_mdns, mock_rdns):
        # Pretend all tools exist
        mock_which.return_value = '/usr/bin/true'
        # arp-scan finds two hosts with MAC+vendor
        mock_arp.return_value = [
            {"ip": "192.168.0.2", "mac": "00:11:22:33:44:02", "vendor": "V1"},
            {"ip": "192.168.0.10", "mac": "00:11:22:33:44:0A", "vendor": "V2"},
        ]
        # nmap finds an extra host not in arp-scan
        mock_nmap.return_value = ["192.168.0.2", "192.168.0.10", "192.168.0.3"]
        # nbtscan gives a name for .3
        mock_nbts.return_value = {"192.168.0.3": "WINHOST<00>"}
        # ip neigh returns a refined MAC for .3
        mock_neigh.side_effect = lambda ip: {"ip": ip, "mac": "AA:BB:CC:DD:EE:FF", "dev": "wlo1", "state": "REACHABLE"} if ip == "192.168.0.3" else {"ip": ip, "mac": "", "dev": "", "state": ""}
        # mdns returns name for .2
        mock_mdns.side_effect = lambda ip, timeout=30: "printer.local" if ip == "192.168.0.2" else None
        # rdns returns for .10
        mock_rdns.side_effect = lambda ip: "server.local" if ip == "192.168.0.10" else None

        hosts = self.main.aggregate_hosts("192.168.0.0/24", interface=None, timeout=10)
        ips = [h['ip'] for h in hosts]
        self.assertEqual(ips, ['192.168.0.2', '192.168.0.3', '192.168.0.10'])
        # merged fields
        h2 = next(h for h in hosts if h['ip'] == '192.168.0.2')
        self.assertEqual(h2['hostname'], 'printer.local')
        h3 = next(h for h in hosts if h['ip'] == '192.168.0.3')
        self.assertEqual(h3['mac'], 'AA:BB:CC:DD:EE:FF')
        h10 = next(h for h in hosts if h['ip'] == '192.168.0.10')
        self.assertEqual(h10['hostname'], 'server.local')

    def test_output_table_and_csv_and_json(self):
        hosts = [
            {"ip": "192.168.0.2", "hostname": "host2.local", "mac": "00:11:22:33:44:02", "vendor": "V1"},
            {"ip": "192.168.0.10", "hostname": "", "mac": "", "vendor": ""},
        ]
        # Capture table output
        buf = io.StringIO()
        saved_stdout = sys.stdout
        try:
            sys.stdout = buf
            self.main.output_table(hosts)
        finally:
            sys.stdout = saved_stdout
        table_out = buf.getvalue()
        self.assertIn('IP', table_out)
        self.assertIn('192.168.0.2', table_out)

        # CSV
        buf = io.StringIO()
        self.main.output_csv(hosts, buf)
        csv_out = buf.getvalue().strip().splitlines()
        self.assertEqual(csv_out[0], 'ip,hostname,mac,vendor')
        self.assertIn('192.168.0.2,host2.local,00:11:22:33:44:02,V1', csv_out[1])

        # JSON
        buf = io.StringIO()
        self.main.output_json(hosts, buf)
        data = json.loads(buf.getvalue())
        self.assertEqual(data[0]['ip'], '192.168.0.2')


if __name__ == '__main__':
    unittest.main(verbosity=2)
