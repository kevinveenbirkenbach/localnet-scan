import unittest
from unittest.mock import patch
from scanners.nmap import _parse_nmap_grepable, NmapPingScanner

class TestScannerNmap(unittest.TestCase):
    def test_parse_nmap_grepable(self):
        raw = (
            "# Nmap scan\n"
            "Host: 192.168.0.10 ()\tStatus: Up\n"
            "Host: 192.168.0.11 ()\tStatus: Up\n"
            "# end\n"
        )
        ips = _parse_nmap_grepable(raw)
        self.assertEqual(ips, ["192.168.0.10", "192.168.0.11"])

    @patch("scanners.nmap.which", return_value="/usr/bin/nmap")
    @patch("scanners.nmap.run", return_value=(0, "Host: 192.168.0.3 ()\tStatus: Up\n", ""))
    def test_scan_ips(self, m_run, m_which):
        s = NmapPingScanner()
        ips = s.scan_ips("192.168.0.0/24", timeout=5)
        self.assertEqual(ips, ["192.168.0.3"])
