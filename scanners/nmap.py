from __future__ import annotations
from typing import List
from utils import run, which

def _parse_nmap_grepable(raw: str) -> List[str]:
    ips: List[str] = []
    for line in raw.splitlines():
        if line.startswith("Host:"):
            fields = line.split()
            if len(fields) >= 2:
                ips.append(fields[1])
    return ips

class NmapPingScanner:
    def scan_ips(self, subnet: str, *, timeout: int) -> List[str]:
        if not which("nmap"):
            return []
        rc, out, _ = run(["nmap", "-sn", "-n", subnet], timeout=timeout)
        if rc != 0 or not out:
            return []
        return _parse_nmap_grepable(out)
