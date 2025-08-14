import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import pandas as pd
import xml.etree.ElementTree as ET
from pyoso import Client

try:
    import tomllib # Python 3.11+
except Exception:
    tomllib = None
try:
    import toml # Fallback for <3.11
except Exception:
    toml = None

def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _snapshot_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return None


def _read_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _read_toml(path: Path) -> Optional[dict]:
    try:
        if tomllib:
            return tomllib.loads(path.read_text(encoding="utf-8"))
        if toml:
            return toml.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return None


def _git_clone(url: str, dest: Path, token: Optional[str]) -> bool:
    if token:
        url = re.sub(r"^https://", f"https://{token}@", url)
    retries = int(os.getenv("SBOM_GIT_CLONE_RETRIES", "2"))
    timeout_seconds = int(os.getenv("SBOM_GIT_CLONE_TIMEOUT", "120"))
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    for attempt in range(retries + 1):
        cmd = ["git", "clone", "--depth", "1", "--no-tags", url, str(dest)]
        try:
            cp = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=timeout_seconds, env=env)
            if cp.returncode == 0:
                return True
        except subprocess.TimeoutExpired:
            pass
        # Cleanup and retry
        shutil.rmtree(dest, ignore_errors=True)
    return False


def _git_head_sha(repo_dir: Path) -> Optional[str]:
    try:
        cp = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"], check=False, capture_output=True, text=True, timeout=int(os.getenv("SBOM_GIT_CMD_TIMEOUT", "60")))
        return cp.stdout.strip() if cp.returncode == 0 else None
    except subprocess.TimeoutExpired:
        return None


def _find_files(root: Path, filename: str) -> List[Path]:
    return [p for p in root.rglob(filename)]

