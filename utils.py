from __future__ import annotations
import shutil
import subprocess
from typing import List, Optional, Tuple

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def run(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
