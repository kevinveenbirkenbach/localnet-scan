import unittest
from unittest.mock import patch
from scanners.seed_arp import SeedArpCacheScanner

class TestScannerSeedArp(unittest.TestCase):
    @patch("scanners.seed_arp.list_ip_neigh_all", return_value=["192.168.0.2", "192.168.0.3"])
    def test_seed_from_arp_cache(self, m_list):
        s = SeedArpCacheScanner()
        hosts = s.scan_hosts("192.168.0.0/24", timeout=5, interface=None)
        ips = [h.ip for h in hosts]
        self.assertEqual(ips, ["192.168.0.2", "192.168.0.3"])
