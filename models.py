from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

@dataclass
class Host:
    ip: str
    hostname: Optional[str] = None
    mac: str = ""
    vendor: str = ""

    def merge_from(self, other: "Host") -> None:
        if not self.mac and other.mac:
            self.mac = other.mac
        if not self.vendor and other.vendor:
            self.vendor = other.vendor
        if not self.hostname and other.hostname:
            self.hostname = other.hostname
