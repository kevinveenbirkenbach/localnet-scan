from __future__ import annotations
import re
from typing import List
from models import Host
from utils import run, which

def _parse_arp_scan_output(raw: str) -> List[Host]:
    hosts: List[Host] = []
    for line in raw.splitlines():
        line = line.strip()
        if re.match(r"^\d+\.\d+\.\d+\.\d+\s+([0-9A-Fa-f:]{17})", line):
            parts = re.split(r"\s{2,}|\t|\s+", line, maxsplit=2)
            ip = parts[0]
            mac = parts[1] if len(parts) > 1 else ""
            vendor = parts[2] if len(parts) > 2 else ""
            hosts.append(Host(ip=ip, mac=mac, vendor=vendor))
    return hosts

class ArpScanScanner:
    def scan_hosts(self, subnet: str, *, timeout: int, interface: str | None = None) -> List[Host]:
        if not which("arp-scan"):
            return []
        cmd = ["arp-scan", "-I", interface, subnet] if interface else ["arp-scan", "--localnet"]
        rc, out, _ = run(cmd, timeout=timeout)
        if rc != 0 or not out:
            return []
        return _parse_arp_scan_output(out)
