from __future__ import annotations
import re
from typing import List
from models import Host
from resolvers import list_ip_neigh_all

class SeedArpCacheScanner:
    """Passive seed: collect IPs from local ARP/neighbour cache."""
    def scan_hosts(self, subnet: str, *, timeout: int, interface: str | None = None) -> List[Host]:
        hosts: List[Host] = []
        for ip in list_ip_neigh_all():
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                hosts.append(Host(ip=ip))
        return hosts
