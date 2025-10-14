from __future__ import annotations
import re
import socket
from typing import Dict, Optional
from utils import run, which

def probe_ip_neigh_one(ip: str) -> Dict[str, str]:
    if which("ip"):
        rc, out, _ = run(["ip", "neigh", "show", ip])
        if rc == 0 and out:
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            line = next((l for l in lines if l.startswith(ip)), lines[0])
            tokens = line.split()
            res = {"ip": ip, "mac": "", "dev": "", "state": ""}
            try:
                i = tokens.index("dev")
                if i + 1 < len(tokens): res["dev"] = tokens[i + 1]
            except ValueError:
                pass
            try:
                j = tokens.index("lladdr")
                if j + 1 < len(tokens): res["mac"] = tokens[j + 1]
            except ValueError:
                pass
            for t in reversed(tokens):
                if t.isupper():
                    res["state"] = t
                    break
            if not res["state"] and tokens:
                res["state"] = tokens[-1]
            return res

    if which("arp"):
        rc, out, _ = run(["arp", "-an"])
        if rc == 0 and out:
            for line in out.splitlines():
                if ip in line:
                    m = re.search(r"([0-9A-Fa-f:]{17})", line)
                    mac = m.group(1) if m else ""
                    return {"ip": ip, "mac": mac, "dev": "", "state": ""}
    return {"ip": ip, "mac": "", "dev": "", "state": ""}

def list_ip_neigh_all() -> list[str]:
    ips: list[str] = []
    if which("ip"):
        rc, out, _ = run(["ip", "-4", "neigh", "show"])
        if rc == 0 and out:
            for line in out.splitlines():
                line = line.strip()
                if not line or "FAILED" in line:
                    continue
                m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\b", line)
                if m:
                    ips.append(m.group(1))
    return ips

def resolve_mdns(ip: str, timeout: int) -> Optional[str]:
    if not which("avahi-resolve-address"):
        return None
    rc, out, _ = run(["avahi-resolve-address", ip], timeout=timeout)
    if rc == 0 and out:
        return out.split()[-1].strip()
    return None

def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def run_nbtscan_range(subnet: str, timeout: int) -> Dict[str, str]:
    if not which("nbtscan"):
        return {}
    rc, out, _ = run(["nbtscan", subnet], timeout=timeout)
    res: Dict[str, str] = {}
    if rc != 0 or not out:
        return res
    for line in out.splitlines():
        parts = re.split(r"\s+", line.strip())
        if parts and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
            res[parts[0]] = parts[1]
    return res
