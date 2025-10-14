import unittest
from unittest.mock import patch
import cli

class TestCli(unittest.TestCase):
    @patch("cli.which", return_value="/usr/bin/ip")
    @patch("cli.run", return_value=(0, "2: wlo1    inet 192.168.0.110/24 brd 192.168.0.255 scope global", ""))
    def test_detect_subnet_auto_via_ip(self, m_run, m_which):
        cidr = cli.detect_subnet(auto=True, provided=None)
        self.assertEqual(cidr, "192.168.0.110/24")

    def test_detect_subnet_provided(self):
        cidr = cli.detect_subnet(auto=False, provided="10.0.0.0/24")
        self.assertEqual(cidr, "10.0.0.0/24")

    def test_build_pipeline_shapes(self):
        pipe = cli.build_pipeline(interface=None, timeout=5, deep=True, no_arpscan=False)
        # sanity: has scanners lists with at least one element each
        self.assertTrue(len(pipe.host_scanners) >= 1)
        self.assertTrue(len(pipe.ip_scanners) >= 1)
