"""Private storage for local protocol 3 bootstrap keys."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional


def default_path() -> Path:
    root = os.environ.get("XDG_CONFIG_HOME")
    if root:
        return Path(root) / "instantpot-local" / "credentials.json"
    return Path.home() / ".config" / "instantpot-local" / "credentials.json"


def normalize_mac(mac: str) -> str:
    clean = mac.replace(":", "").replace("-", "").lower()
    if len(clean) != 12:
        raise ValueError("MAC address must contain six bytes")
    bytes.fromhex(clean)
    return clean


def load_bootstrap_key(mac: str, path: Optional[Path] = None) -> Optional[bytes]:
    target = path or default_path()
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
        value = document["devices"][normalize_mac(mac)]["bootstrap_key"]
        key = bytes.fromhex(value)
    except (FileNotFoundError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return key if len(key) == 32 else None


def save_bootstrap_key(mac: str, ssid: str, key: bytes,
                       path: Optional[Path] = None) -> Path:
    if len(key) != 32:
        raise ValueError("protocol 3 bootstrap key must contain 32 bytes")
    target = path or default_path()
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        document = {"version": 1, "devices": {}}
    if not isinstance(document.get("devices"), dict):
        document["devices"] = {}
    document["version"] = 1
    document["devices"][normalize_mac(mac)] = {
        "ssid": ssid,
        "bootstrap_key": key.hex(),
    }
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, target)
        target.chmod(0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return target

