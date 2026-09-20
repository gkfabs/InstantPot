"""Command-line interface for local Instant Pot control."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .sst import provision as sst_provision, self_test as sst_self_test

from .client import InstantPot, discover
from .credentials import load_bootstrap_key, save_bootstrap_key
from .protocol import ScriptStep, Timer, validate
from .transport import derive_wifi_key


def _json(value) -> None:
    if hasattr(value, "as_dict"):
        value = value.as_dict()
    elif hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    elif isinstance(value, bytes):
        value = {"raw_hex": value.hex().upper()}
    print(json.dumps(value, indent=2, sort_keys=True))


def _pot(args) -> InstantPot:
    device_id = args.device_id
    device = None
    if args.direct_ap:
        device_id = 0 if device_id is None else device_id
    elif device_id is None:
        found = discover(host=args.host, timeout=args.timeout)
        if not found:
            raise RuntimeError(f"no discovery response from {args.host}")
        matches = [d for d in found if d.appliance_type == 0xEC] or found
        if len(matches) != 1:
            raise RuntimeError("more than one device found; specify --device-id")
        device = matches[0]
        device_id = device.device_id
        if args.host == "255.255.255.255":
            args.host = device.host
    protocol = 2 if args.direct_ap else (args.protocol or (device.protocol if device else 2))
    mac = args.mac or (device.mac if device else None)
    token = bytes.fromhex(args.token) if args.token else None
    key = bytes.fromhex(args.key) if args.key else None
    password = None
    bootstrap_key = None
    direct_secret = None
    if args.direct_ap:
        direct_secret = getpass.getpass("Instant Pot Secret Key: ")
    if protocol == 3 and args.ssid and token is None and key is None:
        if mac:
            bootstrap_key = load_bootstrap_key(mac)
        if bootstrap_key is None:
            password = getpass.getpass(f"Wi-Fi password for {args.ssid!r}: ")
            bootstrap_key = derive_wifi_key(
                args.ssid, password, bytes.fromhex(mac.replace(":", "").replace("-", ""))
            )
            args._save_bootstrap = (mac, args.ssid, bootstrap_key)
    elif protocol == 3 and token is None and key is None and mac:
        bootstrap_key = load_bootstrap_key(mac)
    return InstantPot(
        args.host, device_id, port=args.port, timeout=args.timeout,
        protocol=protocol, wifi_ssid=args.ssid, wifi_password=password,
        mac=mac, bootstrap_key=bootstrap_key, token=token, key=key,
        direct_secret=direct_secret,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="instantpot-local",
        description="Cloud-free control for the 2018 Instant Pot Smart WiFi")
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("discover", help="find cookers with UDP/6445")
    d.add_argument("--host", default="255.255.255.255")
    d.add_argument("--timeout", type=float, default=2.0)

    sub.add_parser("self-test", help="test SST cryptography and framing offline")

    p = sub.add_parser("provision", help="run the validated SST SoftAP provisioner")
    p.add_argument("--host", default="192.168.1.1")
    p.add_argument("--port", type=int, default=6444)
    p.add_argument("--ssid", required=True)
    p.add_argument("--bssid")
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--hello-delay", type=float, default=0.03)
    p.add_argument("--command-delay", type=float, default=0.02)
    p.add_argument("--try-wifi-after-secret-0001", action="store_true")
    p.add_argument("--post-wait", type=float, default=1.0)
    p.add_argument("--no-save-credentials", action="store_true",
                   help="do not store the derived local key")

    for name, help_text in (
        ("status", "query and decode cooker status"),
        ("time-info", "query factory date and clock"),
        ("stop", "stop/cancel cooking"),
        ("sound", "enable or mute keypad sound"),
        ("timer", "set stored timer 1 or 2"),
        ("preset", "start a cooking preset"),
        ("script", "upload/start a DIY script from JSON"),
        ("timezone", "send the APK clock and numeric time-zone command"),
        ("raw", "send an exact AA/EC payload"),
        ("close-wifi", "send the destructive Wi-Fi-disable command"),
    ):
        q = sub.add_parser(name, help=help_text)
        q.add_argument("--host", required=True)
        q.add_argument("--device-id", type=int,
                       help="decimal device ID; discovered automatically when omitted")
        q.add_argument("--port", type=int, default=6444)
        q.add_argument("--timeout", type=float, default=5.0)
        q.add_argument("--protocol", type=int, choices=(2, 3),
                       help="transport version; discovered automatically when omitted")
        q.add_argument("--direct-ap", action="store_true",
                       help="use the cooker setup network and verify its Secret Key")
        q.add_argument("--ssid",
                       help="home Wi-Fi SSID for local protocol 3 authentication")
        q.add_argument("--mac",
                       help="cooker MAC address; discovered automatically when omitted")
        q.add_argument("--token",
                       help="128-digit hexadecimal LAN token from an existing pairing")
        q.add_argument("--key",
                       help="hexadecimal LAN key from an existing pairing")

    sound = sub.choices["sound"]
    sound.add_argument("state", choices=("on", "off", "mute", "unmute"))
    timer = sub.choices["timer"]
    timer.add_argument("number", type=int, choices=(1, 2))
    timer.add_argument("minutes", type=int)
    preset = sub.choices["preset"]
    preset.add_argument("name")
    preset.add_argument("--adjust", default="normal", choices=("normal", "more", "less"))
    preset.add_argument("--pressure", default="high", choices=("low", "high"))
    preset.add_argument("--cook-time", type=int, default=0)
    preset.add_argument("--pressure-time", type=int)
    preset.add_argument("--keep-warm", action="store_true")
    preset.add_argument("--delay-time", type=int)
    preset.add_argument("--timer", type=int, choices=(1, 2), default=1)
    script = sub.choices["script"]
    script.add_argument("json_file", help="JSON array, or object containing a steps array")
    script.add_argument("--recipe-id", type=int, default=0)
    script.add_argument("--instruction-index", type=int, default=0)
    script.add_argument("--delay-time", type=int)
    script.add_argument("--timer", type=int, choices=(1, 2), default=1)
    timezone = sub.choices["timezone"]
    timezone.add_argument("zone_id", type=int,
                          help="numeric ID from the APK zoneIdentifyList (not a UTC offset)")
    raw = sub.choices["raw"]
    raw.add_argument("hex_payload")
    close = sub.choices["close-wifi"]
    close.add_argument("--yes", action="store_true",
                       help="confirm that loss of cooker Wi-Fi connectivity is intended")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "discover":
            _json([asdict(d) for d in discover(host=args.host, timeout=args.timeout)])
            return 0
        if args.command == "self-test":
            return sst_self_test()
        if args.command == "provision":
            if not args.no_save_credentials:
                def save_credentials(ssid, password, mac):
                    bootstrap = derive_wifi_key(ssid, password, mac)
                    target = save_bootstrap_key(mac.hex(), ssid, bootstrap)
                    print(f"[+] Saved the derived local key in {target}")
                args.credential_callback = save_credentials
            return sst_provision(args)
        pot = _pot(args)
        if args.command == "status": result = pot.status()
        elif args.command == "time-info": result = pot.time_info()
        elif args.command == "stop": result = pot.stop()
        elif args.command == "sound": result = pot.set_sound(args.state in ("on", "unmute"))
        elif args.command == "timer": result = pot.set_timer(args.number - 1, args.minutes)
        elif args.command == "preset":
            result = pot.start_preset(args.name, adjust=args.adjust, pressure=args.pressure,
                cook_time=args.cook_time, pressure_time=args.pressure_time,
                keep_warm=args.keep_warm, delay_time=args.delay_time, timer=args.timer - 1)
        elif args.command == "script":
            with open(args.json_file, encoding="utf-8") as stream:
                doc = json.load(stream)
            raw_steps = doc["steps"] if isinstance(doc, dict) else doc
            steps = [ScriptStep(**step) for step in raw_steps]
            result = [x.hex().upper() for x in pot.start_script(steps,
                recipe_id=args.recipe_id, instruction_index=args.instruction_index,
                delay_time=args.delay_time, timer=args.timer - 1)]
        elif args.command == "timezone": result = pot.set_timezone(args.zone_id)
        elif args.command == "raw":
            payload = bytes.fromhex(args.hex_payload)
            validate(payload)
            result = pot.raw(payload)
        elif args.command == "close-wifi":
            if not args.yes:
                parser.error("close-wifi requires --yes; the cooker will lose Wi-Fi connectivity")
            result = pot.close_wifi()
        else:
            parser.error("unknown command")
        pending = getattr(args, "_save_bootstrap", None)
        if pending:
            save_bootstrap_key(*pending)
        _json(result)
        return 0
    except (OSError, ValueError, RuntimeError, TimeoutError) as exc:
        print(f"instantpot-local: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
