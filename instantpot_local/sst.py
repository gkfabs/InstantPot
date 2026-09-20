"""
instantpot_local.sst

Standalone Python implementation of the 2018 Instant Pot Smart WiFi / Midea
"third generation" SST provisioning path recovered from the original APK.

What is implemented:
  * Midea SST 5A5A frame creation/parsing
  * fixed-key AES-128-ECB/PKCS#7 payload crypto
  * fixed-suffix MD5 frame authenticator
  * SET_SECRET_KEY (0x0075 -> 0x8075)
  * WRITE_WIFI_CONFIGURATION (0x0070 -> 0x8070)
  * initial signed SST hello (0x007B)
  * response verification/decryption
  * optional BSSID field
  * fresh 16-byte random code
  * no cloud, Android, Java, or vendor app

IMPORTANT:
  This program provisions an Instant Pot that is ALREADY in its Instant_Pot_*
  SoftAP/reset state. It does NOT yet issue the factory/network-reset command
  to a cooker that is currently joined to the home LAN. That reset operation
  is a different appliance command and was not part of the captured successful
  SST provisioning transaction. Do not guess it.

Project setup:
    mise install
    mise run sync

Typical use after putting the cooker in Wi-Fi setup/reset mode:
    mise run instantpot -- provision --ssid YOUR_2G_SSID

The computer must be connected to the Instant_Pot_* AP first. The cooker is
normally 192.168.1.1:6444 in that state.

Secrets are prompted with getpass and are never printed.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import secrets
import socket
import string
import struct
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
except ImportError:
    print("Missing dependency: cryptography", file=sys.stderr)
    print("Install project dependencies with: mise run sync", file=sys.stderr)
    raise SystemExit(3)


# Recovered from libmsmart.so.  The native eaes32WithoutKey() hashes this
# constant with MD5 to obtain the AES-128 key.  emd5WithoutKey() computes
# MD5(message || this constant).
_NATIVE_FIXED = b"xhdiwjnchekd4d512chdjx5d8e4c394D2D7S"
_AES_KEY = hashlib.md5(_NATIVE_FIXED).digest()

MAGIC = b"\x5a\x5a"
SST_VERSION = 0x01
SST_SIGNED = 0x10
SST_ENCRYPTED = 0x01

CMD_HELLO = 0x007B
CMD_SET_SECRET = 0x0075
RSP_SET_SECRET = 0x8075
CMD_WIFI = 0x0070
RSP_WIFI = 0x8070
CMD_SECRET_INTERMEDIATE = 0x8076

DEFAULT_HOST = "192.168.1.1"
DEFAULT_PORT = 6444


def aes_encrypt(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(_AES_KEY), modes.ECB()).encryptor()
    return enc.update(padded) + enc.finalize()


def aes_decrypt(data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise ValueError(f"encrypted payload length {len(data)} is not a multiple of 16")
    dec = Cipher(algorithms.AES(_AES_KEY), modes.ECB()).decryptor()
    padded = dec.update(data) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def frame_md5(data_without_digest: bytes) -> bytes:
    return hashlib.md5(data_without_digest + _NATIVE_FIXED).digest()


def timestamp8(now: Optional[datetime] = None) -> bytes:
    """
    Exact Calendar layout used by V.c():
      [millisecond low byte, second, minute, Calendar.HOUR (0..11),
       day, Calendar.MONTH (0..11), YY, CC]
    """
    now = now or datetime.now()
    return bytes((
        (now.microsecond // 1000) & 0xFF,
        now.second & 0xFF,
        now.minute & 0xFF,
        (now.hour % 12) & 0xFF,
        now.day & 0xFF,
        (now.month - 1) & 0xFF,
        (now.year % 100) & 0xFF,
        (now.year // 100) & 0xFF,
    ))


def build_frame(
    payload: bytes,
    command: int,
    message_id: int,
    *,
    encrypt: bool = True,
    sign: bool = True,
    device_id6: bytes = b"\x00" * 6,
    now: Optional[datetime] = None,
) -> bytes:
    if len(device_id6) != 6:
        raise ValueError("device_id6 must be exactly six bytes")
    if encrypt:
        payload = aes_encrypt(payload)

    flags = (SST_ENCRYPTED if encrypt else 0) | (SST_SIGNED if sign else 0)
    # V.c(): fixed data begins at offset 0x28 (40), and 16 bytes are reserved
    # at the end for emd5WithoutKey.  Thus total = payload + 56.
    total = 56 + len(payload)
    out = bytearray(total)
    out[0:2] = MAGIC
    out[2] = SST_VERSION
    out[3] = flags
    out[4:6] = struct.pack("<H", total)
    out[6:8] = struct.pack("<H", command & 0xFFFF)
    out[8:12] = struct.pack("<I", message_id & 0xFFFFFFFF)
    out[12:20] = timestamp8(now)
    out[20:26] = device_id6
    # 26:40 remain zero exactly as in the APK builder.
    out[40:40 + len(payload)] = payload
    if sign:
        out[-16:] = frame_md5(bytes(out[:-16]))
    return bytes(out)


def build_hello(now: Optional[datetime] = None) -> bytes:
    # Captured connect-time SST packet:
    # flags=sign only, command=0x7B, message=0, one zero payload byte.
    return build_frame(
        b"\x00", CMD_HELLO, 0, encrypt=False, sign=True, now=now
    )


def secret_payload(secret: str) -> bytes:
    raw = secret.encode("utf-8")
    if len(raw) < 6:
        raise ValueError("Secret Key must be at least 6 bytes")
    if len(raw) > 255:
        raise ValueError("Secret Key is too long")
    if not secret.isalnum():
        raise ValueError("The original app accepts only alphanumeric Secret Keys")
    # aK.a(): seven zero bytes, one-byte length, then secret bytes.
    return b"\x00" * 7 + bytes((len(raw),)) + raw


def parse_bssid(text: Optional[str]) -> bytes:
    if not text:
        return b""
    clean = text.replace(":", "").replace("-", "").strip()
    if len(clean) != 12:
        raise ValueError("BSSID must contain exactly six hex bytes")
    try:
        return bytes.fromhex(clean)
    except ValueError as e:
        raise ValueError("Invalid BSSID") from e


def wifi_payload(random_code: bytes, ssid: str, password: str,
                 bssid: Optional[str] = None) -> bytes:
    if len(random_code) != 16:
        raise ValueError("random_code must be exactly 16 bytes")
    ssid_b = ssid.encode("utf-8")
    password_b = password.encode("utf-8")
    bssid_b = parse_bssid(bssid)

    if len(ssid_b) > 255:
        raise ValueError("SSID is too long")
    if len(password_b) > 255:
        raise ValueError("Wi-Fi password is too long")

    # aL.a():
    #   random[16] | ssid_len | ssid | password_len | password |
    #   bssid_len(0 or 6) | bssid[6 if present]
    return (
        random_code
        + bytes((len(ssid_b),)) + ssid_b
        + bytes((len(password_b),)) + password_b
        + bytes((len(bssid_b),)) + bssid_b
    )


def new_random_code() -> bytes:
    # The successful SDK trace used a 16-character ASCII random code.
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(16)).encode("ascii")



# Standard Midea V2 UDP discovery used by this WFM111 module.
DISCOVERY_PACKET = bytes([
    0x5A,0x5A,0x01,0x11,0x48,0x00,0x92,0x00,
    *([0] * 32),
    0x7F,0x75,0xBD,0x6B,0x3E,0x4F,0x8B,0x76,
    0x2E,0x84,0x9C,0x6E,0x57,0x8D,0x65,0x90,
    0x03,0x6E,0x9D,0x43,0x42,0xA5,0x0F,0x1F,
    0x56,0x9E,0xB8,0xEC,0x91,0x8E,0x92,0xE5,
])
DISCOVERY_KEY = bytes.fromhex("6a92ef406bad2f0359baad994171ea6d")


def discover_ap(host: str, timeout: float = 2.0):
    """Read-only UDP/6445 discovery. Returns decrypted payload and basic fields."""
    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    us.settimeout(timeout)
    try:
        us.sendto(DISCOVERY_PACKET, (host, 6445))
        raw, peer = us.recvfrom(2048)
    finally:
        us.close()
    if len(raw) < 56 or raw[:2] != MAGIC:
        raise ValueError("unexpected UDP discovery response")
    enc = raw[40:-16]
    dec = Cipher(algorithms.AES(DISCOVERY_KEY), modes.ECB()).decryptor()
    padded = dec.update(enc) + dec.finalize()
    try:
        u = padding.PKCS7(128).unpadder()
        plain = u.update(padded) + u.finalize()
    except ValueError:
        plain = padded
    serial = plain[8:40].decode("ascii", errors="replace").rstrip("\x00") if len(plain) >= 40 else ""
    ssid = ""
    if len(plain) > 40:
        n = plain[40]
        ssid = plain[41:41+n].decode("ascii", errors="replace")
    return peer[0], serial, ssid, plain


@dataclass
class SSTFrame:
    raw: bytes
    flags: int
    command: int
    message_id: int
    payload_encrypted: bytes
    payload: bytes


def parse_frame(raw: bytes) -> SSTFrame:
    if len(raw) < 56:
        raise ValueError(f"SST frame too short: {len(raw)}")
    if raw[:2] != MAGIC:
        raise ValueError(f"bad SST magic: {raw[:2].hex()}")
    total = struct.unpack_from("<H", raw, 4)[0]
    if total != len(raw):
        raise ValueError(f"SST length says {total}, received {len(raw)}")

    flags = raw[3]
    command = struct.unpack_from("<H", raw, 6)[0]
    message_id = struct.unpack_from("<I", raw, 8)[0]

    if flags & SST_SIGNED:
        expected = frame_md5(raw[:-16])
        if expected != raw[-16:]:
            raise ValueError("SST MD5 authenticator mismatch")

    encrypted = raw[40:-16]
    payload = aes_decrypt(encrypted) if (flags & SST_ENCRYPTED) else encrypted
    return SSTFrame(raw, flags, command, message_id, encrypted, payload)


class SSTSocket:
    def __init__(self, host: str, port: int, timeout: float):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.buf = bytearray()

    def __enter__(self):
        s = socket.create_connection((self.host, self.port), self.timeout)
        s.settimeout(self.timeout)
        self.sock = s
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass

    def send(self, frame: bytes):
        assert self.sock is not None
        self.sock.sendall(frame)

    def recv_frame(self, deadline: Optional[float] = None) -> SSTFrame:
        assert self.sock is not None
        deadline = deadline or (time.monotonic() + self.timeout)

        while True:
            # Resynchronize on 5A5A.
            pos = self.buf.find(MAGIC)
            if pos > 0:
                del self.buf[:pos]
            elif pos < 0 and len(self.buf) > 1:
                self.buf[:] = self.buf[-1:]

            if len(self.buf) >= 6 and self.buf[:2] == MAGIC:
                total = struct.unpack_from("<H", self.buf, 4)[0]
                if total < 56 or total > 65535:
                    del self.buf[0]
                    continue
                if len(self.buf) >= total:
                    raw = bytes(self.buf[:total])
                    del self.buf[:total]
                    return parse_frame(raw)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for SST response")
            self.sock.settimeout(min(self.timeout, remaining))
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("device closed TCP connection")
            self.buf.extend(chunk)

    def wait_response(self, command: int, message_id: int,
                      timeout: Optional[float] = None,
                      verbose: bool = True) -> SSTFrame:
        deadline = time.monotonic() + (timeout or self.timeout)
        while True:
            f = self.recv_frame(deadline)
            if verbose:
                print(
                    f"    <- command=0x{f.command:04X} message={f.message_id} "
                    f"payload={f.payload.hex().upper()}"
                )
            if f.command == command and f.message_id == message_id:
                return f
            # SET_SECRET_KEY emits an intermediate 0x8076 challenge/status
            # before the actual 0x8075 response.  It is intentionally ignored.


def provision(args) -> int:
    secret = getpass.getpass(
        "Instant Pot Secret Key (use the existing key if the reset retained it): "
    )
    secret2 = getpass.getpass("Repeat Secret Key: ")
    if secret != secret2:
        print("[-] Secret Keys do not match.", file=sys.stderr)
        return 2
    password = getpass.getpass(f"Wi-Fi password for {args.ssid!r}: ")

    try:
        sp = secret_payload(secret)
        random_code = new_random_code()
        wp = wifi_payload(random_code, args.ssid, password, args.bssid)
    except ValueError as e:
        print(f"[-] {e}", file=sys.stderr)
        return 2
    discovered_mac = None

    print(f"[*] Read-only UDP discovery of {args.host}:6445")
    try:
        peer, serial, ap_ssid, plain = discover_ap(args.host, args.timeout)
        print(f"[+] Discovery: ip={peer} ssid={ap_ssid!r} serial={serial!r}")
        # Keep this diagnostic non-secret.  It is useful for comparing reset states.
        print(f"    discovery tail={plain[-24:].hex().upper()}")
        ssid_size = plain[40] if len(plain) > 40 else 0
        mac_offset = 63 + ssid_size
        if len(plain) >= mac_offset + 6:
            candidate = plain[mac_offset:mac_offset + 6]
            if candidate != b"\x00" * 6:
                discovered_mac = candidate
    except Exception as e:
        print(f"[!] Discovery did not complete ({e}); continuing with TCP.")

    print(f"[*] Connecting to Instant Pot SoftAP endpoint {args.host}:{args.port}")
    try:
        with SSTSocket(args.host, args.port, args.timeout) as sock:
            print("[+] TCP connected")

            print("[*] SST hello")
            sock.send(build_hello())
            # The captured SDK waited ~22 ms between hello and SET_SECRET_KEY.
            time.sleep(args.hello_delay)

            print("[*] SET_SECRET_KEY / verify-secret transaction")
            sock.send(build_frame(sp, CMD_SET_SECRET, 1))
            rsp = sock.wait_response(RSP_SET_SECRET, 1)

            if rsp.payload == b"\x00\x00":
                print("[+] New Secret Key accepted (0000)")
            elif rsp.payload == b"\x00\x01":
                print("[+] Existing Secret Key verified (0001)")
            elif rsp.payload == b"\x00\x02":
                raise RuntimeError("Secret Key verification failed (0002)")
            else:
                raise RuntimeError(
                    f"unexpected SET_SECRET_KEY response {rsp.payload.hex().upper()}"
                )

            time.sleep(args.command_delay)
            print("[*] WRITE_WIFI_CONFIGURATION")
            sock.send(build_frame(wp, CMD_WIFI, 2))
            rsp = sock.wait_response(RSP_WIFI, 2)
            if rsp.payload != b"\x00":
                raise RuntimeError(
                    "WRITE_WIFI_CONFIGURATION rejected: "
                    f"response {rsp.payload.hex().upper()}"
                )
            print("[+] Wi-Fi configuration accepted (00)")
            callback = getattr(args, "credential_callback", None)
            if callback and discovered_mac is not None:
                try:
                    callback(args.ssid, password, discovered_mac)
                except (OSError, ValueError) as e:
                    print(f"[!] Could not save the derived local key: {e}")
            print("[*] Cooker should now switch from SoftAP to STA.")
            time.sleep(args.post_wait)

    except (OSError, TimeoutError, ConnectionError, ValueError, RuntimeError) as e:
        print(f"[-] Provisioning failed: {e}", file=sys.stderr)
        return 5

    password = ""
    print("[+] SST provisioning transaction completed.")
    print(f"[*] Reconnect this computer to {args.ssid!r} and locate the cooker via DHCP/discovery.")
    return 0


def self_test() -> int:
    # Non-secret deterministic protocol tests.
    sample_secret = "TestKey7"
    plain = secret_payload(sample_secret)
    encrypted = aes_encrypt(plain)
    if aes_decrypt(encrypted) != plain:
        raise AssertionError("AES round trip failed")

    fixed_time = datetime(2026, 9, 17, 21, 55, 22, 66000)
    f = build_frame(plain, CMD_SET_SECRET, 1, now=fixed_time)
    p = parse_frame(f)
    assert p.command == CMD_SET_SECRET
    assert p.message_id == 1
    assert p.payload == plain
    assert len(f) == 56 + len(aes_encrypt(plain))

    rc = b"ABCDEFGHIJKLMNOP"
    wp = wifi_payload(rc, "TestSSID", "TestPassword", None)
    f2 = build_frame(wp, CMD_WIFI, 2, now=fixed_time)
    p2 = parse_frame(f2)
    assert p2.payload == wp
    assert p2.command == CMD_WIFI

    hello = build_hello(fixed_time)
    ph = parse_frame(hello)
    assert ph.command == CMD_HELLO and ph.payload == b"\x00"
    assert len(hello) == 57

    print("[+] Crypto/frame self-test passed.")
    print(f"[+] AES key derivation: MD5(native fixed constant) -> {len(_AES_KEY)} bytes")
    print("[+] SET_SECRET_KEY and WRITE_WIFI_CONFIGURATION builders passed.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Standalone SST provisioner for 2018 Instant Pot Smart WiFi"
    )
    sub = ap.add_subparsers(dest="command", required=True)

    sub.add_parser("self-test", help="test crypto/framing locally; sends nothing")

    p = sub.add_parser(
        "provision",
        help="provision cooker while computer is connected to Instant_Pot_* SoftAP",
    )
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--ssid", required=True, help="target 2.4 GHz Wi-Fi SSID")
    p.add_argument(
        "--bssid",
        help="optional AP BSSID aa:bb:cc:dd:ee:ff; normally omit it",
    )
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--hello-delay", type=float, default=0.03,
                   help="delay after SST hello; captured SDK used about 22 ms")
    p.add_argument("--command-delay", type=float, default=0.02)
    p.add_argument("--try-wifi-after-secret-0001", action="store_true",
                   help="deprecated compatibility flag; 0001 is a successful verification")
    p.add_argument("--post-wait", type=float, default=1.0)

    args = ap.parse_args()
    if args.command == "self-test":
        return self_test()
    if args.command == "provision":
        return provision(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
