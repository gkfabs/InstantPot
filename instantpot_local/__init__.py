"""Local-only client for the 2018 Instant Pot Smart WiFi."""

from .client import InstantPot, discover
from .protocol import (
    Adjust,
    CommandType,
    KeepWarm,
    Preset,
    PressureLevel,
    ScriptStep,
    build_preset,
    build_script,
    build_status_query,
    parse_status,
)

__all__ = [
    "Adjust",
    "CommandType",
    "InstantPot",
    "KeepWarm",
    "Preset",
    "PressureLevel",
    "ScriptStep",
    "build_preset",
    "build_script",
    "build_status_query",
    "discover",
    "parse_status",
]

__version__ = "0.1.0"
