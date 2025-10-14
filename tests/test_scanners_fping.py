import unittest
from unittest.mock import patch
from scanners.fping import FpingSweepScanner

class TestScannerFping(unittest.TestCase):
    @patch("scanners.fping.which", return_value="/usr/bin/fping")
    @patch("scanners.fping.run", return_value=(0, "192.168.0.2\n192.168.0.3\n", ""))
    def test_scan_ips(self, m_run, m_which):
        s = FpingSweepScanner()
        ips = s.scan_ips("192.168.0.0/24", timeout=5)
        self.assertEqual(ips, ["192.168.0.2", "192.168.0.3"])
