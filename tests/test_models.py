import unittest
from models import Host

class TestModels(unittest.TestCase):
    def test_merge_from_prefers_existing_and_fills_missing(self):
        a = Host(ip="192.168.0.10", hostname=None, mac="", vendor="")
        b = Host(ip="192.168.0.10", hostname="server.local", mac="00:11:22:33:44:55", vendor="V1")
        a.merge_from(b)
        self.assertEqual(a.hostname, "server.local")
        self.assertEqual(a.mac, "00:11:22:33:44:55")
        self.assertEqual(a.vendor, "V1")

        # existing values should remain if present
        c = Host(ip="192.168.0.10", hostname="keepme", mac="aa:bb:cc:dd:ee:ff", vendor="KeepV")
        a.merge_from(c)
        self.assertEqual(a.hostname, "server.local")  # unchanged, because already set
        self.assertEqual(a.mac, "00:11:22:33:44:55")
        self.assertEqual(a.vendor, "V1")
