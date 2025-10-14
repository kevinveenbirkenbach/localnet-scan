import unittest
from unittest.mock import patch

import resolvers

class TestResolvers(unittest.TestCase):
    @patch("resolvers.which", side_effect=lambda c: "/usr/bin/ip" if c=="ip" else None)
    @patch("resolvers.run", return_value=(0, "192.168.0.204 dev wlo1 lladdr 00:23:57:4c:66:21 STALE", ""))
    def test_probe_ip_neigh_one(self, m_run, m_which):
        res = resolvers.probe_ip_neigh_one("192.168.0.204")
        self.assertEqual(res["mac"].lower(), "00:23:57:4c:66:21")
        self.assertEqual(res["dev"], "wlo1")
        self.assertEqual(res["state"], "STALE")

    @patch("resolvers.which", side_effect=lambda c: "/usr/bin/avahi-resolve-address" if c=="avahi-resolve-address" else None)
    @patch("resolvers.run", return_value=(0, "192.168.0.42\thostname.local", ""))
    def test_resolve_mdns(self, m_run, m_which):
        name = resolvers.resolve_mdns("192.168.0.42", timeout=5)
        self.assertEqual(name, "hostname.local")

    @patch("resolvers.which", side_effect=lambda c: "/usr/bin/ip" if c=="ip" else None)
    @patch("resolvers.run", return_value=(0, "192.168.0.1 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE\n192.168.0.2 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE", ""))
    def test_list_ip_neigh_all(self, m_run, m_which):
        ips = resolvers.list_ip_neigh_all()
        self.assertEqual(ips, ["192.168.0.1", "192.168.0.2"])

    @patch("resolvers.which", side_effect=lambda c: "/usr/bin/nbtscan" if c=="nbtscan" else None)
    @patch("resolvers.run", return_value=(0, "192.168.0.50    ALPHA<00>  UNIQUE\n192.168.0.51    BETA<00>  UNIQUE", ""))
    def test_run_nbtscan_range(self, m_run, m_which):
        res = resolvers.run_nbtscan_range("192.168.0.0/24", timeout=10)
        self.assertEqual(res["192.168.0.50"], "ALPHA<00>")
        self.assertEqual(res["192.168.0.51"], "BETA<00>")
