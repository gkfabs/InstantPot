import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
from unittest.mock import patch

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from instantpot_local.protocol import (
    CommandType, Preset, ScriptStep, build_preset, build_script,
    build_close_wifi, build_set_sound, build_set_timer, build_status_query,
    build_stop, validate,
)
from instantpot_local.transport import (
    CONTROL_COMMAND, LocalTransport, _aes_cbc, _unwrap_v3_data, _wrap_v3_data,
    derive_wifi_key, parse_discovery,
)
from instantpot_local.credentials import load_bootstrap_key, save_bootstrap_key
from instantpot_local.sst import DISCOVERY_KEY, build_frame, parse_frame


class ProtocolTests(unittest.TestCase):

    def test_credential_store_round_trip(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "credentials.json"
            key = bytes(range(32))
            save_bootstrap_key("f0:c9:d1:7d:65:14", "<WIFI_SSID>", key, path)
            self.assertEqual(load_bootstrap_key("F0C9D17D6514", path), key)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
    def test_status_query_exact(self):
        msg = build_status_query()
        self.assertEqual(msg.hex(), "aa14ec00000000000003aa550003000000000000fb")
        validate(msg)

    def test_preset_offsets(self):
        msg = build_preset("manual", adjust="more", pressure="low", cook_time=37,
                           keep_warm=True, delay_time=90, timer=1)
        self.assertEqual(msg[14], Preset.MANUAL)
        self.assertEqual(msg[18], CommandType.DELAYED_EXECUTE)
        self.assertEqual(msg[19:21], bytes((1, 0)))
        self.assertEqual(msg[25:31], bytes((0, 37, 0, 37, 1, 30)))
        self.assertEqual(msg[33:35], bytes((1, 1)))
        validate(msg)

    def test_stop_sound_timer(self):
        self.assertEqual(build_stop()[18], CommandType.STANDBY)
        self.assertEqual(build_set_sound(False)[35], 0)
        timer = build_set_timer(1, 7 * 60 + 30)
        self.assertEqual(timer[18], CommandType.SET_TIMER)
        self.assertEqual(timer[29:31], bytes((7, 30)))
        self.assertEqual(timer[34], 1)
        close = build_close_wifi()
        self.assertEqual(close[:12].hex(), "aa0cec000000000000680000")
        validate(close)

    def test_script_layout(self):
        msg = build_script([ScriptStep("heat_to_temperature",
            heat_to_temperature=80, duration=15)], recipe_id=0x010203,
            instruction_index=4)[0]
        self.assertEqual(msg[13], 0x20)
        self.assertEqual(msg[14:18], bytes((4, 3, 2, 1)))
        self.assertEqual(msg[20:23], bytes((2, 2, 18)))
        self.assertEqual(msg[41], 1)  # first real step index after dummy step
        self.assertEqual(msg[42], 1)  # HeatToTemperature
        self.assertEqual(msg[46], 80)
        validate(msg)

    def test_large_script_is_chunked_like_apk(self):
        commands = build_script([ScriptStep("pause") for _ in range(128)])
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0][21], 129)
        self.assertEqual(commands[1][21], 129)
        self.assertEqual(commands[1][23], 128)

    def test_control_envelope_reuses_sst(self):
        payload = build_status_query()
        device = 123456789
        frame = build_frame(payload, CONTROL_COMMAND, 7,
                            device_id6=device.to_bytes(6, "little"))
        parsed = parse_frame(frame)
        self.assertEqual(parsed.payload, payload)
        self.assertEqual(parsed.command, 0x20)
        self.assertEqual(frame[20:26], device.to_bytes(6, "little"))

    def test_v3_discovery_unwrap(self):
        plain = (bytes((192, 168, 4, 124)) + (6444).to_bytes(4, "little")
                 + b"0000EC1110002001618A271103550000"
                 + bytes((16,)) + b"Instant_Pot_Test")
        pad = padding.PKCS7(128).padder()
        padded = pad.update(plain) + pad.finalize()
        enc = Cipher(algorithms.AES(DISCOVERY_KEY), modes.ECB()).encryptor()
        encrypted = enc.update(padded) + enc.finalize()
        header = bytearray(40)
        header[:2] = b"\x5a\x5a"
        header[20:26] = (151732607748927).to_bytes(6, "little")
        inner = bytes(header) + encrypted + bytes(16)
        wrapped = b"\x83\x70" + (len(inner) + 16).to_bytes(2, "big") + bytes(4) + inner + bytes(16)
        device = parse_discovery(wrapped, "192.168.4.124")
        self.assertEqual(device.protocol, 3)
        self.assertEqual(device.device_id, 151732607748927)
        self.assertEqual(device.port, 6444)
        self.assertEqual(device.serial, "0000EC1110002001618A271103550000")
        self.assertEqual(device.ssid, "Instant_Pot_Test")

    def test_v3_wifi_key_matches_apk_algorithm(self):
        key = derive_wifi_key(
            "<WIFI_SSID>", "example-password", bytes.fromhex("f0c9d17d6514")
        )
        self.assertEqual(
            key.hex(),
            "d71ddceeaab71d8657f45ab0d7a9c9ff4c8bed99fe8399bc8999aa03241ff35d",
        )

    def test_v3_data_envelope(self):
        key = bytes(range(32))
        payload = build_frame(build_status_query(), CONTROL_COMMAND, 9,
                              device_id6=bytes.fromhex("010203040506"))
        request = bytearray(_wrap_v3_data(payload, key, 1))
        # The APK sends type 6 and receives type 3. The encrypted body layout
        # is identical in both directions.
        request[5] = (request[5] & 0xF0) | 3
        plain = _aes_cbc(request[6:-32], key, encrypt=False)
        request[-32:] = hashlib.sha256(request[:6] + plain).digest()
        unpacked, count = _unwrap_v3_data(bytes(request), key)
        self.assertEqual(count, 1)
        self.assertEqual(unpacked, payload)

    def test_v3_local_key_agreement(self):
        class MemorySocket:
            def __init__(self, response):
                self.response = bytearray(response)
                self.sent = bytearray()

            def sendall(self, data):
                self.sent.extend(data)

            def recv(self, size):
                data = bytes(self.response[:size])
                del self.response[:size]
                return data

        client_key = bytes(range(32))
        device_key = bytes(range(32, 64))
        encrypted = _aes_cbc(device_key, client_key, encrypt=True)
        response = (b"\x83\x70\x00\x40\x20\x01\x00\x00" + encrypted
                    + hashlib.sha256(device_key).digest())
        memory_socket = MemorySocket(response)
        transport = LocalTransport(
            "unused", 1, protocol=3, wifi_ssid="<WIFI_SSID>",
            wifi_password="example-password", mac="f0:c9:d1:7d:65:14",
        )
        with patch("instantpot_local.transport.secrets.token_bytes",
                   return_value=client_key):
            session_key = transport._authenticate_v3(memory_socket)
        request = bytes(memory_socket.sent)
        self.assertEqual(request[:8], b"\x83\x70\x00\x40\x20\x00\x00\x00")
        bootstrap = derive_wifi_key(
            "<WIFI_SSID>", "example-password", bytes.fromhex("f0c9d17d6514")
        )
        self.assertEqual(_aes_cbc(request[8:40], bootstrap, encrypt=False),
                         client_key)
        self.assertEqual(request[40:], hashlib.sha256(client_key).digest())
        self.assertEqual(session_key,
                         bytes(a ^ b for a, b in zip(client_key, device_key)))


if __name__ == "__main__":
    unittest.main()
