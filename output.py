from __future__ import annotations
import json
from typing import List
from models import Host

def output_table(hosts: List[Host]) -> str:
    rows = [["IP", "Hostname", "MAC", "Vendor"]]
    for h in hosts:
        rows.append([h.ip, h.hostname or "", h.mac or "", h.vendor or ""])
    widths = [max(len(str(r[i])) for r in rows) for i in range(4)]
    lines = []
    for r in rows:
        lines.append("  ".join(str(r[i]).ljust(widths[i]) for i in range(4)))
    return "\n".join(lines)

def output_csv(hosts: List[Host]) -> str:
    lines = ["ip,hostname,mac,vendor"]
    for h in hosts:
        lines.append(f"{h.ip},{h.hostname or ''},{h.mac or ''},{h.vendor or ''}")
    return "\n".join(lines)

def output_json(hosts: List[Host]) -> str:
    payload = [dict(ip=h.ip, hostname=h.hostname or "", mac=h.mac or "", vendor=h.vendor or "") for h in hosts]
    return json.dumps(payload, indent=2)

def output_ansible(hosts: List[Host]) -> str:
    lines = ["[scanned]"]
    for h in hosts:
        lines.append(h.hostname or h.ip)
    return "\n".join(lines)
