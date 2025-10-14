#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
from typing import Optional

from aggregate import DiscoveryPipeline
from models import Host
from output import output_ansible, output_csv, output_json, output_table
from scanners import ArpScanScanner, FpingSweepScanner, NmapPingScanner, SeedArpCacheScanner
from utils import which, run

def detect_subnet(auto: bool, provided: Optional[str]) -> str:
    if provided:
        return provided
    if not auto:
        raise SystemExit("Please provide --subnet or use --auto to auto-detect your primary IPv4 CIDR.")
    if which("ip"):
        rc, out, _ = run(["ip", "-4", "-o", "addr", "show", "scope", "global"])
        if rc == 0 and out:
            first = out.splitlines()[0].strip().split()
            for token in first:
                if "/" in token and token.count('.') == 3:
                    return token
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith("127."):
            return ip + "/24"
    except Exception:
        pass
    raise SystemExit("Could not auto-detect subnet. Provide --subnet like 192.168.0.0/24.")

def build_pipeline(interface: Optional[str], timeout: int, deep: bool, no_arpscan: bool) -> DiscoveryPipeline:
    host_scanners = [SeedArpCacheScanner()]
    if not no_arpscan:
        host_scanners.append(ArpScanScanner())

    ip_scanners = [NmapPingScanner()]
    if deep:
        ip_scanners.append(FpingSweepScanner())

    return DiscoveryPipeline(
        host_scanners=host_scanners,
        ip_scanners=ip_scanners,
        timeout=timeout,
        interface=interface,
        enable_nbtscan=True,
        enable_mdns=True,
        enable_rdns=True,
    )

def main():
    parser = argparse.ArgumentParser(
        description="Local network scanner using Strategy-pattern scanners (arp-scan/nmap/fping) and resolvers."
    )
    parser.add_argument("--subnet", "-s", help="CIDR to scan, e.g. 192.168.0.0/24")
    parser.add_argument("--auto", action="store_true", help="Auto-detect primary IPv4 CIDR (uses `ip` output)")
    parser.add_argument("--interface", "-i", help="Interface to use for arp-scan (optional)")
    parser.add_argument("--format", "-f", choices=["table", "csv", "json", "ansible"], default="table", help="Output format")
    parser.add_argument("--output", "-o", help="Output file (if omitted prints to stdout)")
    parser.add_argument("--timeout", type=int, default=30, help="Global timeout per external tool in seconds")
    parser.add_argument("--no-arpscan", action="store_true", help="Do not try arp-scan even if available")
    parser.add_argument("--deep", action="store_true", help="Do a deeper discovery (fping sweep + full ARP cache seed)")
    parser.add_argument("--version", action="version", version="localnet 1.1.0")

    args = parser.parse_args()
    subnet = detect_subnet(args.auto, args.subnet)

    pipeline = build_pipeline(args.interface, args.timeout, args.deep, args.no_arpscan)
    hosts = pipeline.discover(subnet)

    if args.format == "table":
        content = output_table(hosts)
    elif args.format == "csv":
        content = output_csv(hosts)
    elif args.format == "json":
        content = output_json(hosts)
    else:
        content = output_ansible(hosts)

    if args.output:
        with open(args.output, "w") as f:
            f.write(content + ("\n" if not content.endswith("\n") else ""))
    else:
        print(content)

if __name__ == "__main__":
    main()
