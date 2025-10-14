import unittest
from unittest.mock import patch
from models import Host
from aggregate import DiscoveryPipeline

class DummyHostScanner:
    def __init__(self, hosts):
        self._hosts = hosts
    def scan_hosts(self, subnet, *, timeout, interface=None):
        return list(self._hosts)

class DummyIpScanner:
    def __init__(self, ips):
        self._ips = ips
    def scan_ips(self, subnet, *, timeout):
        return list(self._ips)

class TestAggregate(unittest.TestCase):
    @patch("aggregate.reverse_dns", side_effect=lambda ip: "server.local" if ip=="192.168.0.10" else None)
    @patch("aggregate.resolve_mdns", side_effect=lambda ip, timeout=30: "printer.local" if ip=="192.168.0.2" else None)
    @patch("aggregate.probe_ip_neigh_one", side_effect=lambda ip: {"ip": ip, "mac": "AA:BB:CC:DD:EE:FF" if ip=="192.168.0.3" else "", "dev":"", "state":""})
    @patch("aggregate.run_nbtscan_range", return_value={"192.168.0.3": "WINHOST<00>"})
    def test_pipeline_merge_enrich_sort(self, m_nbts, m_probe, m_mdns, m_rdns):
        host_scanners = [DummyHostScanner([
            Host(ip="192.168.0.2", mac="00:11:22:33:44:02", vendor="V1"),
            Host(ip="192.168.0.10", mac="00:11:22:33:44:0A", vendor="V2"),
        ])]
        ip_scanners = [DummyIpScanner(["192.168.0.2", "192.168.0.10", "192.168.0.3"])]

        pipe = DiscoveryPipeline(host_scanners, ip_scanners, timeout=10, interface=None)
        hosts = pipe.discover("192.168.0.0/24")
        ips = [h.ip for h in hosts]
        self.assertEqual(ips, ["192.168.0.2", "192.168.0.3", "192.168.0.10"])

        h2 = next(h for h in hosts if h.ip == "192.168.0.2")
        self.assertEqual(h2.hostname, "printer.local")
        h3 = next(h for h in hosts if h.ip == "192.168.0.3")
        self.assertEqual(h3.mac, "AA:BB:CC:DD:EE:FF")
        self.assertTrue(h3.hostname.startswith("WINHOST"))
        h10 = next(h for h in hosts if h.ip == "192.168.0.10")
        self.assertEqual(h10.hostname, "server.local")
