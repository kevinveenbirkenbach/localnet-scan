from __future__ import annotations
from typing import Dict, Iterable, List, Optional, Set, Tuple
from models import Host
from resolvers import probe_ip_neigh_one, resolve_mdns, reverse_dns, run_nbtscan_range
from scanners import Scanner, HostScanner, IpScanner

class DiscoveryPipeline:
    """
    Facade/Coordinator: orchestrates Scanners (Strategy) and resolution steps.
    """

    def __init__(
        self,
        host_scanners: Iterable[HostScanner],
        ip_scanners: Iterable[IpScanner],
        *,
        timeout: int = 30,
        interface: Optional[str] = None,
        enable_nbtscan: bool = True,
        enable_mdns: bool = True,
        enable_rdns: bool = True,
    ):
        self.host_scanners = list(host_scanners)
        self.ip_scanners = list(ip_scanners)
        self.timeout = timeout
        self.interface = interface
        self.enable_nbtscan = enable_nbtscan
        self.enable_mdns = enable_mdns
        self.enable_rdns = enable_rdns

    def discover(self, subnet: str) -> List[Host]:
        hosts_by_ip: Dict[str, Host] = {}

        # 1) Host-yielding scanners (e.g., arp-scan, ARP seed)
        for scanner in self.host_scanners:
            for h in scanner.scan_hosts(subnet, timeout=self.timeout, interface=self.interface):
                hosts_by_ip[h.ip] = self._merged(hosts_by_ip.get(h.ip), h)

        # 2) IP-only scanners (e.g., nmap ping, fping sweep)
        seed_ips: Set[str] = set(hosts_by_ip.keys())
        for scanner in self.ip_scanners:
            for ip in scanner.scan_ips(subnet, timeout=self.timeout):
                seed_ips.add(ip)
        for ip in seed_ips:
            hosts_by_ip.setdefault(ip, Host(ip=ip))

        # 3) Enrichment (MAC, hostname via mDNS/NetBIOS/RDNS)
        nbts = run_nbtscan_range(subnet, timeout=self.timeout) if self.enable_nbtscan else {}
        for ip, host in list(hosts_by_ip.items()):
            neigh = probe_ip_neigh_one(ip)
            if neigh.get("mac"):
                host.mac = neigh["mac"]

            if self.enable_mdns and not host.hostname:
                name = resolve_mdns(ip, timeout=self.timeout)
                if name:
                    host.hostname = name

            if not host.hostname and ip in nbts:
                host.hostname = nbts[ip]

            if self.enable_rdns and not host.hostname:
                rd = reverse_dns(ip)
                if rd:
                    host.hostname = rd

        # 4) Sort by numeric IP
        return sorted(hosts_by_ip.values(), key=lambda h: tuple(map(int, h.ip.split("."))))

    @staticmethod
    def _merged(a: Optional[Host], b: Host) -> Host:
        if a is None:
            return b
        a.merge_from(b)
        return a
