import unittest
from unittest.mock import patch
from scanners.arp_scan import _parse_arp_scan_output, ArpScanScanner

class TestScannerArpScan(unittest.TestCase):
    def test_parse_arp_scan_output(self):
        raw = (
            "Interface: wlo1, datalink type: EN10MB (Ethernet)\n"
            "192.168.0.1\t00:11:22:33:44:55\tRouter Inc\n"
            "192.168.0.42\tAA:BB:CC:DD:EE:FF\tDevice Co\n"
            "2 packets received by filter, 0 packets dropped by kernel\n"
        )
        hosts = _parse_arp_scan_output(raw)
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0].ip, "192.168.0.1")
        self.assertEqual(hosts[0].mac, "00:11:22:33:44:55")
        self.assertEqual(hosts[0].vendor, "Router Inc")
        self.assertEqual(hosts[1].ip, "192.168.0.42")
        self.assertEqual(hosts[1].mac, "AA:BB:CC:DD:EE:FF")

    @patch("scanners.arp_scan.which", return_value="/usr/bin/arp-scan")
    @patch("scanners.arp_scan.run", return_value=(0, "192.168.0.2\t00:aa:bb:cc:dd:ee\tV\n", ""))
    def test_scan_hosts(self, m_run, m_which):
        s = ArpScanScanner()
        hosts = s.scan_hosts("192.168.0.0/24", timeout=5, interface=None)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].ip, "192.168.0.2")
