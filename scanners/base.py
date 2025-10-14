from __future__ import annotations
from typing import List, Protocol
from models import Host

class IpScanner(Protocol):
    def scan_ips(self, subnet: str, *, timeout: int) -> List[str]:
        ...

class HostScanner(Protocol):
    def scan_hosts(self, subnet: str, *, timeout: int, interface: str | None = None) -> List[Host]:
        ...

# Marker type for union-like typing in Aggregator
Scanner = IpScanner | HostScanner
