"""Local UDP discovery and TCP SST transport."""

from __future__ import annotations

import socket
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Optional

from .sst import (
    CMD_SET_SECRET,
    DEFAULT_PORT,
    DISCOVERY_KEY,
    DISCOVERY_PACKET,
    MAGIC,
    RSP_SET_SECRET,
    SSTSocket,
    build_frame,
    build_hello,
    parse_frame,
    secret_payload,
)
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CONTROL_COMMAND = 0x0020
CONTROL_RESPONSE = 0x8020


@dataclass(frozen=True)
class DiscoveredDevice:
    host: str
    port: int
    device_id: int
    serial: str
    ssid: str
    appliance_type: Optional[int]
    protocol: int
    mac: Optional[str]
    random_code: Optional[str]
    configured: Optional[bool]
    secret_key_exists: Optional[bool]
    raw_hex: str


def parse_discovery(raw: bytes, host: str = "") -> DiscoveredDevice:
    original = raw
    protocol = 2
    # Protocol-v3 modules wrap the normal 5A5A discovery response in an
    # 8370 packet. The APK's bq parser handles this form. The inner packet is
    # still encrypted with the same discovery key and has the same layout.
    if raw[:2] == b"\x83\x70" and len(raw) >= 24 and raw[8:10] == MAGIC:
        declared = int.from_bytes(raw[2:4], "big")
        if declared + 8 != len(raw):
            raise ValueError("bad 8370 discovery length")
        raw = raw[8:-16]
        protocol = 3
    if len(raw) < 56 or raw[:2] != MAGIC:
        raise ValueError("unexpected Midea discovery response")
    encrypted = raw[40:-16]
    dec = Cipher(algorithms.AES(DISCOVERY_KEY), modes.ECB()).decryptor()
    padded = dec.update(encrypted) + dec.finalize()
    try:
        unpad = padding.PKCS7(128).unpadder()
        plain = unpad.update(padded) + unpad.finalize()
    except ValueError:
        plain = padded
    serial = plain[8:40].decode("ascii", "replace").rstrip("\x00") if len(plain) >= 40 else ""
    ssid = ""
    if len(plain) > 40:
        size = plain[40]
        ssid = plain[41:41 + size].decode("ascii", "replace")
    device_id = int.from_bytes(raw[20:26], "little")
    advertised_port = int.from_bytes(plain[4:8], "little") if len(plain) >= 8 else 0
    appliance_type = 0xEC if serial.startswith("0000EC") else None
    mac = None
    random_code = None
    configured = None
    secret_key_exists = None
    if ssid:
        # aR.a(): after the variable SSID, the MAC starts 63 bytes later.
        mac_offset = 63 + len(ssid.encode("ascii", "replace"))
        if len(plain) >= mac_offset + 6:
            mac_bytes = plain[mac_offset:mac_offset + 6]
            if mac_bytes != b"\x00" * 6:
                mac = mac_bytes.hex(":")
        # aR.a() stores this 16-byte provisioning value in aR.k.
        random_offset = 78 + len(ssid.encode("ascii", "replace"))
        if len(plain) >= random_offset + 16:
            value = plain[random_offset:random_offset + 16]
            if any(value):
                random_code = value.decode("ascii", "replace")
        if len(plain) >= random_offset + 18:
            configured = plain[random_offset + 16] == 1
            secret_key_exists = plain[random_offset + 17] == 1
    return DiscoveredDevice(host, advertised_port or DEFAULT_PORT, device_id,
                            serial, ssid, appliance_type, protocol, mac,
                            random_code, configured, secret_key_exists,
                            original.hex().upper())


def discover(*, host: str = "255.255.255.255", timeout: float = 2.0,
             port: int = 6445) -> list[DiscoveredDevice]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(min(timeout, 0.25))
    devices: dict[tuple[str, int], DiscoveredDevice] = {}
    deadline = time.monotonic() + timeout
    try:
        sock.sendto(DISCOVERY_PACKET, (host, port))
        while time.monotonic() < deadline:
            try:
                raw, peer = sock.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                device = parse_discovery(raw, peer[0])
            except ValueError:
                # A busy UDP socket can receive unrelated broadcast traffic.
                # Ignore it, but fail normally if no valid device is found.
                continue
            devices[(device.host, device.device_id)] = device
    finally:
        sock.close()
    return list(devices.values())


class LocalTransport:
    def __init__(self, host: str, device_id: int, *, port: int = DEFAULT_PORT,
                 timeout: float = 5.0, protocol: int = 2,
                 wifi_ssid: Optional[str] = None,
                 wifi_password: Optional[str] = None,
                 mac: Optional[str] = None,
                 bootstrap_key: Optional[bytes] = None,
                 direct_secret: Optional[str] = None,
                 token: Optional[bytes] = None,
                 key: Optional[bytes] = None):
        self.host = host
        self.device_id = device_id
        self.port = port
        self.timeout = timeout
        self.protocol = protocol
        self.wifi_ssid = wifi_ssid
        self.wifi_password = wifi_password
        self.mac = _parse_mac(mac) if mac else None
        self.bootstrap_key = bootstrap_key
        self.direct_secret = direct_secret
        self.token = token
        self.key = key
        self._message_id = 1

    @property
    def device_id6(self) -> bytes:
        if not 0 <= self.device_id < 1 << 48:
            raise ValueError("device_id must fit in the six-byte SST field")
        return self.device_id.to_bytes(6, "little")

    def send(self, appliance_payload: bytes) -> bytes:
        message_id = self._message_id
        self._message_id = 1 if message_id == 0xFFFFFFFF else message_id + 1
        frame = build_frame(appliance_payload, CONTROL_COMMAND, message_id,
                            device_id6=self.device_id6)
        if self.direct_secret is not None:
            return self._send_direct(frame, message_id)
        if self.protocol == 3:
            return self._send_v3(frame, message_id)
        with SSTSocket(self.host, self.port, self.timeout) as sock:
            sock.send(frame)
            response = sock.wait_response(CONTROL_RESPONSE, message_id, verbose=False)
        return response.payload

    def _send_direct(self, frame: bytes, message_id: int) -> bytes:
        with SSTSocket(self.host, self.port, self.timeout) as sock:
            sock.send(build_hello())
            time.sleep(0.03)
            sock.send(build_frame(secret_payload(self.direct_secret), CMD_SET_SECRET, 1))
            verified = sock.wait_response(RSP_SET_SECRET, 1, verbose=False)
            if len(verified.payload) < 2 or verified.payload[1] == 2:
                raise ValueError("Instant Pot Secret Key verification failed")
            sock.send(frame)
            response = sock.wait_response(CONTROL_RESPONSE, message_id, verbose=False)
        return response.payload

    def _send_v3(self, frame: bytes, message_id: int) -> bytes:
        with socket.create_connection((self.host, self.port), self.timeout) as sock:
            sock.settimeout(self.timeout)
            session_key = self._authenticate_v3(sock)
            sock.sendall(_wrap_v3_data(frame, session_key, 1))
            while True:
                packet = _recv_v3_packet(sock)
                inner, _count = _unwrap_v3_data(packet, session_key)
                response = parse_frame(inner)
                if (response.command == CONTROL_RESPONSE and
                        response.message_id == message_id):
                    return response.payload

    def _authenticate_v3(self, sock: socket.socket) -> bytes:
        bootstrap = self.token is None and self.key is None
        if self.token is not None or self.key is not None:
            if self.token is None or self.key is None:
                raise ValueError("protocol 3 requires both token and key")
            if len(self.token) != 64 or len(self.key) not in (16, 24, 32):
                raise ValueError("protocol 3 token must be 64 bytes and key must be an AES key")
            client_key = self.key
            request = b"\x83\x70\x00\x40\x20\x00\x00\x00" + self.token
        else:
            if self.bootstrap_key is not None:
                if len(self.bootstrap_key) != 32:
                    raise ValueError("protocol 3 bootstrap key must contain 32 bytes")
                bootstrap_key = self.bootstrap_key
            elif not self.wifi_ssid or self.wifi_password is None or self.mac is None:
                raise ValueError(
                    "protocol 3 needs saved credentials, one-time --ssid setup, "
                    "or --token and --key"
                )
            else:
                bootstrap_key = derive_wifi_key(
                    self.wifi_ssid, self.wifi_password, self.mac
                )
            client_key = secrets.token_bytes(32)
            encrypted = _aes_cbc(client_key, bootstrap_key, encrypt=True)
            request = (b"\x83\x70\x00\x40\x20\x00\x00\x00" + encrypted
                       + hashlib.sha256(client_key).digest())
        sock.sendall(request)
        response = _recv_v3_packet(sock)
        response_type = response[5] & 0x0F
        if response_type == 0x0F:
            detail = response[8:].rstrip(b"\x00").decode("ascii", "replace")
            suffix = f": {detail}" if detail else ""
            if bootstrap:
                suffix += (
                    "; bootstrap authentication failed; a recovered --token and --key "
                    "pair can use the other APK path"
                )
            raise ValueError(f"protocol 3 key agreement rejected{suffix}")
        if len(response) != 72 or response_type != 1:
            raise ValueError(
                "unexpected protocol 3 key-agreement response "
                f"(type={response_type}, length={len(response)}, "
                f"header={response[:8].hex().upper()})"
            )
        device_key = _aes_cbc(response[8:40], client_key, encrypt=False)
        if hashlib.sha256(device_key).digest() != response[40:72]:
            raise ValueError("protocol 3 key-agreement digest mismatch")
        return bytes(a ^ b for a, b in zip(client_key, device_key))


def _parse_mac(value: str) -> bytes:
    clean = value.replace(":", "").replace("-", "")
    if len(clean) != 12:
        raise ValueError("MAC address must contain six bytes")
    try:
        return bytes.fromhex(clean)
    except ValueError as exc:
        raise ValueError("invalid MAC address") from exc


def derive_wifi_key(ssid: str, password: str, mac: bytes) -> bytes:
    """Implement bs.a(String,String,byte[]) from the 2018 SDK."""
    if len(mac) != 6:
        raise ValueError("MAC address must contain six bytes")
    return hashlib.sha256(ssid.encode() + password.encode() + mac).digest()


def _aes_cbc(data: bytes, key: bytes, *, encrypt: bool) -> bytes:
    if len(data) % 16:
        raise ValueError("protocol 3 AES data must use complete blocks")
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes(16)))
    worker = cipher.encryptor() if encrypt else cipher.decryptor()
    return worker.update(data) + worker.finalize()


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    out = bytearray()
    while len(out) < length:
        chunk = sock.recv(length - len(out))
        if not chunk:
            raise ConnectionError("device closed TCP connection")
        out.extend(chunk)
    return bytes(out)


def _recv_v3_packet(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 6)
    if header[:2] != b"\x83\x70":
        raise ValueError("unexpected protocol 3 TCP response")
    declared = int.from_bytes(header[2:4], "big")
    total = declared + 8
    if total < 8 or total > 65543:
        raise ValueError("invalid protocol 3 TCP packet length")
    return header + _recv_exact(sock, total - 6)


def _wrap_v3_data(payload: bytes, key: bytes, count: int) -> bytes:
    plain = count.to_bytes(2, "big") + payload
    padding_size = (-len(plain)) % 16
    if padding_size:
        alphabet = b"0123456789abcdef"
        plain += bytes(secrets.choice(alphabet) for _ in range(padding_size))
    encrypted = _aes_cbc(plain, key, encrypt=True)
    total = 6 + len(encrypted) + 32
    header = (b"\x83\x70" + (total - 8).to_bytes(2, "big") + b"\x20"
              + bytes(((padding_size << 4) | 6,)))
    # This 2018 SDK signs the padded plaintext, not the ciphertext. See
    # aB.a([B) at source lines 1375-1394: it pads count + SST data, hashes
    # header + padded plaintext, then encrypts the padded plaintext.
    return header + encrypted + hashlib.sha256(header + plain).digest()


def _unwrap_v3_data(packet: bytes, key: bytes) -> tuple[bytes, int]:
    packet_type = packet[5] & 0x0F
    if packet_type == 0x0F:
        raise RuntimeError("protocol 3 device returned an error packet")
    if packet_type != 3 or len(packet) < 54:
        raise ValueError("unexpected protocol 3 data response")
    plain = _aes_cbc(packet[6:-32], key, encrypt=False)
    # bq.a([B,bv,bm,[B) decrypts first and verifies SHA-256 over the
    # six-byte header plus padded plaintext.
    if hashlib.sha256(packet[:6] + plain).digest() != packet[-32:]:
        raise ValueError("protocol 3 data digest mismatch")
    padding_size = packet[5] >> 4
    if padding_size > len(plain) - 2:
        raise ValueError("invalid protocol 3 data padding")
    end = len(plain) - padding_size if padding_size else len(plain)
    return plain[2:end], int.from_bytes(plain[:2], "big")
