#!/usr/bin/env python3
"""main.py — Local network scanner wrapper

This script aggregates local network discovery using available system
tools (arp-scan, nmap, avahi-resolve, nbtscan, ip, arp, arping) and
falls back to lighter probes if tools are missing.

Output formats: table (default), csv, json, ansible

Usage examples:
  sudo python3 main.py --subnet 192.168.0.0/24 --format csv --output hosts.csv
  python3 main.py --auto --format json
  sudo python3 main.py --subnet 192.168.0.0/24 --ansible
"""

from __future__ import annotations
import argparse
import json
import re
import shutil
import socket
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

# ----------------------- Utilities -----------------------

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def run(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    """Run external command and capture stdout/stderr."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def detect_subnet(auto: bool, provided: Optional[str]) -> str:
    if provided:
        return provided
    if not auto:
        raise SystemExit("Please provide --subnet or use --auto to auto-detect your primary IPv4 CIDR.")
    if which("ip"):
        rc, out, err = run(["ip", "-4", "-o", "addr", "show", "scope", "global"])
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


# ----------------------- Parsers for external tools -----------------------

def parse_arp_scan_output(raw: str) -> List[Dict]:
    hosts: List[Dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if re.match(r"^\d+\.\d+\.\d+\.\d+\s+([0-9A-Fa-f:]{17})", line):
            parts = re.split(r"\s{2,}|\t|\s+", line, maxsplit=2)
            ip = parts[0]
            mac = parts[1] if len(parts) > 1 else ""
            vendor = parts[2] if len(parts) > 2 else ""
            hosts.append({"ip": ip, "mac": mac, "vendor": vendor})
    return hosts


def parse_nmap_grepable(raw: str) -> List[str]:
    ips: List[str] = []
    for line in raw.splitlines():
        if line.startswith("Host:"):
            fields = line.split()
            if len(fields) >= 2:
                ips.append(fields[1])
    return ips


# ----------------------- Scanners -----------------------

def run_arp_scan(interface: Optional[str], subnet: str, timeout: int) -> List[Dict]:
    if not which("arp-scan"):
        return []
    cmd = ["arp-scan", "--localnet"]
    if interface:
        cmd = ["arp-scan", "-I", interface, subnet]
    rc, out, err = run(cmd, timeout=timeout)
    if rc != 0:
        return []
    return parse_arp_scan_output(out)


def run_nmap_hosts(subnet: str, timeout: int) -> List[str]:
    if not which("nmap"):
        return []
    rc, out, err = run(["nmap", "-sn", "-n", subnet], timeout=timeout)
    if rc != 0:
        return []
    return parse_nmap_grepable(out)


def probe_ip_neigh(ip: str) -> Dict:
    """Parse `ip neigh show <ip>` robustly (no fixed positions)."""
    if which("ip"):
        rc, out, err = run(["ip", "neigh", "show", ip])
        if rc == 0 and out:
            # choose the line for this IP (some systems may emit multiple lines)
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            line = next((l for l in lines if l.startswith(ip)), lines[0])
            tokens = line.split()

            d = {"ip": ip, "mac": "", "dev": "", "state": ""}

            # device: token after 'dev'
            try:
                i = tokens.index("dev")
                if i + 1 < len(tokens):
                    d["dev"] = tokens[i + 1]
            except ValueError:
                pass

            # mac: token after 'lladdr'
            try:
                j = tokens.index("lladdr")
                if j + 1 < len(tokens):
                    d["mac"] = tokens[j + 1]
            except ValueError:
                pass

            # state: usually last UPPER token (STALE/REACHABLE/DELAY/FAILED/INCOMPLETE/PROBE/PERMANENT)
            for t in reversed(tokens):
                if t.isupper():
                    d["state"] = t
                    break
            if not d["state"] and tokens:
                d["state"] = tokens[-1]

            return d

    # Fallback to legacy `arp -an`
    if which("arp"):
        rc, out, err = run(["arp", "-an"])
        for line in out.splitlines():
            if ip in line:
                m = re.search(r"([0-9A-Fa-f:]{17})", line)
                mac = m.group(1) if m else ""
                return {"ip": ip, "mac": mac, "dev": "", "state": ""}

    return {"ip": ip, "mac": "", "dev": "", "state": ""}


def resolve_mdns(ip: str, timeout: int) -> Optional[str]:
    if not which("avahi-resolve-address"):
        return None
    rc, out, err = run(["avahi-resolve-address", ip], timeout=timeout)
    if rc == 0 and out:
        return out.split()[-1].strip()
    return None


def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def run_nbtscan_range(subnet: str, timeout: int) -> Dict[str, str]:
    res: Dict[str, str] = {}
    if not which("nbtscan"):
        return res
    rc, out, err = run(["nbtscan", subnet], timeout=timeout)
    if rc != 0:
        return res
    for line in out.splitlines():
        parts = re.split(r"\s+", line.strip())
        if parts and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
            res[parts[0]] = parts[1]
    return res


# ----------------------- Aggregation -----------------------

def aggregate_hosts(subnet: str, interface: Optional[str], timeout: int) -> List[Dict]:
    hosts: Dict[str, Dict] = {}
    if which("arp-scan"):
        try:
            arp_list = run_arp_scan(interface, subnet, timeout)
            for h in arp_list:
                ip = h.get("ip")
                if not ip:
                    continue
                hosts[ip] = {"ip": ip, "mac": h.get("mac", ""), "vendor": h.get("vendor", ""), "hostname": None}
        except Exception:
            pass
    nmap_ips = run_nmap_hosts(subnet, timeout)
    for ip in nmap_ips:
        if ip not in hosts:
            hosts[ip] = {"ip": ip, "mac": "", "vendor": "", "hostname": None}
    nbts = run_nbtscan_range(subnet, timeout)
    for ip in list(hosts.keys()):
        neigh = probe_ip_neigh(ip)
        if neigh.get("mac"):
            hosts[ip]["mac"] = neigh.get("mac")
        mdn = resolve_mdns(ip, timeout)
        if mdn:
            hosts[ip]["hostname"] = mdn
        if ip in nbts:
            hosts[ip]["hostname"] = nbts[ip]
        if not hosts[ip]["hostname"]:
            rd = reverse_dns(ip)
            if rd:
                hosts[ip]["hostname"] = rd
    out = [hosts[k] for k in sorted(hosts.keys(), key=lambda s: tuple(map(int, s.split('.'))))]
    return out


# ----------------------- Output formatting -----------------------

def output_table(hosts: List[Dict]):
    rows: List[List[str]] = []
    headers = ["IP", "Hostname", "MAC", "Vendor"]
    rows.append(headers)
    for h in hosts:
        rows.append([h.get("ip", ""), h.get("hostname") or "", h.get("mac") or "", h.get("vendor") or ""])
    widths = [max(len(str(r[i])) for r in rows) for i in range(len(headers))]
    for r in rows:
        print("  ".join(str(r[i]).ljust(widths[i]) for i in range(len(r))))


def output_csv(hosts: List[Dict], fh):
    fh.write("ip,hostname,mac,vendor\n")
    for h in hosts:
        fh.write(f'{h.get("ip","")},{(h.get("hostname") or "")},{(h.get("mac") or "")},{(h.get("vendor") or "")}\n')


def output_json(hosts: List[Dict], fh):
    fh.write(json.dumps(hosts, indent=2))


def output_ansible(hosts: List[Dict], fh):
    fh.write("[scanned]\n")
    for h in hosts:
        line = h.get("ip", "")
        if h.get("hostname"):
            line = h.get("hostname")
        fh.write(line + "\n")


# ----------------------- CLI -----------------------

def main():
    parser = argparse.ArgumentParser(description="Local network scanner wrapper. Uses arp-scan/nmap/avahi if available.")
    parser.add_argument("--subnet", "-s", help="CIDR to scan, e.g. 192.168.0.0/24")
    parser.add_argument("--auto", action="store_true", help="Auto-detect primary IPv4 CIDR (uses `ip` output)")
    parser.add_argument("--interface", "-i", help="Interface to use for arp-scan (optional)")
    parser.add_argument("--format", "-f", choices=["table", "csv", "json", "ansible"], default="table", help="Output format")
    parser.add_argument("--output", "-o", help="Output file (if omitted prints to stdout)")
    parser.add_argument("--timeout", type=int, default=30, help="Global timeout per external tool in seconds")
    parser.add_argument("--no-arpscan", action="store_true", help="Do not try arp-scan even if available")
    parser.add_argument("--version", action="version", version="main.py 1.0")

    args = parser.parse_args()

    subnet = detect_subnet(args.auto, args.subnet)
    interface = args.interface
    timeout = args.timeout

    if args.no_arpscan:
        global run_arp_scan
        def run_arp_scan(interface: Optional[str], subnet: str, timeout: int) -> List[Dict]:
            return []

    hosts = aggregate_hosts(subnet, interface, timeout)

    fh = open(args.output, "w") if args.output else sys.stdout
    try:
        if args.format == "table":
            output_table(hosts)
        elif args.format == "csv":
            output_csv(hosts, fh)
        elif args.format == "json":
            output_json(hosts, fh)
        elif args.format == "ansible":
            output_ansible(hosts, fh)
    finally:
        if args.output:
            fh.close()


if __name__ == '__main__':
    main()
