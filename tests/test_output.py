import unittest
from models import Host
from output import output_table, output_csv, output_json, output_ansible
import json

class TestOutput(unittest.TestCase):
    def setUp(self):
        self.hosts = [
            Host(ip="192.168.0.2", hostname="host2.local", mac="00:11:22:33:44:02", vendor="V1"),
            Host(ip="192.168.0.10", hostname=None, mac="", vendor=""),
        ]

    def test_output_table(self):
        txt = output_table(self.hosts)
        self.assertIn("IP", txt)
        self.assertIn("192.168.0.2", txt)

    def test_output_csv(self):
        csv_txt = output_csv(self.hosts)
        lines = csv_txt.strip().splitlines()
        self.assertEqual(lines[0], "ip,hostname,mac,vendor")
        self.assertIn("192.168.0.2,host2.local,00:11:22:33:44:02,V1", lines[1])

    def test_output_json(self):
        js = json.loads(output_json(self.hosts))
        self.assertEqual(js[0]["ip"], "192.168.0.2")
        self.assertEqual(js[0]["hostname"], "host2.local")

    def test_output_ansible(self):
        inv = output_ansible(self.hosts)
        self.assertIn("[scanned]", inv.splitlines()[0])
        self.assertIn("host2.local", inv)
