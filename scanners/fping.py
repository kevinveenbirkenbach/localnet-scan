from __future__ import annotations
from typing import List
from utils import run, which

class FpingSweepScanner:
    """Fast ICMP sweep (optional, used in --deep mode)."""
    def scan_ips(self, subnet: str, *, timeout: int) -> List[str]:
        if not which("fping"):
            return []
        cmd = ["fping", "-a", "-g", "-r", "0", "-t", "200", subnet]
        rc, out, _ = run(cmd, timeout=timeout)
        if rc in (0, 1) and out:
            return [l.strip() for l in out.splitlines() if l.strip()]
        return []
