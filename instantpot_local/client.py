"""High-level local Instant Pot API."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable, Optional

from .protocol import (
    Adjust, Preset, PressureLevel, ScriptStep, Timer, build_close_wifi,
    build_preset, build_script, build_set_sound, build_set_timer, build_status_query,
    build_stop, build_time_query, build_timezone, parse_status, parse_time_info,
)
from .transport import DiscoveredDevice, LocalTransport, discover


class InstantPot:
    def __init__(self, host: str, device_id: int, *, port: int = 6444,
                 timeout: float = 5.0, protocol: int = 2,
                 wifi_ssid: Optional[str] = None,
                 wifi_password: Optional[str] = None,
                 mac: Optional[str] = None,
                 bootstrap_key: Optional[bytes] = None,
                 direct_secret: Optional[str] = None,
                 token: Optional[bytes] = None,
                 key: Optional[bytes] = None):
        self.transport = LocalTransport(
            host, device_id, port=port, timeout=timeout, protocol=protocol,
            wifi_ssid=wifi_ssid, wifi_password=wifi_password, mac=mac,
            bootstrap_key=bootstrap_key,
            direct_secret=direct_secret,
            token=token, key=key,
        )

    def raw(self, appliance_payload: bytes) -> bytes:
        return self.transport.send(appliance_payload)

    def status(self):
        return parse_status(self.raw(build_status_query()))

    def time_info(self):
        return parse_time_info(self.raw(build_time_query()))

    def start_preset(self, preset: Preset | int | str, *,
                     adjust: Adjust | int | str = Adjust.NORMAL,
                     pressure: PressureLevel | int | str = PressureLevel.HIGH,
                     cook_time: int = 0, pressure_time: Optional[int] = None,
                     keep_warm: bool = False, delay_time: Optional[int] = None,
                     timer: Timer | int = Timer.TIMER_1):
        payload = build_preset(
            preset, adjust=adjust, pressure=pressure, cook_time=cook_time,
            pressure_time=pressure_time, keep_warm=keep_warm,
            delay_time=delay_time, timer=timer,
        )
        return parse_status(self.raw(payload))

    def start_script(self, steps: Iterable[ScriptStep], *, recipe_id: int = 0,
                     instruction_index: int = 0, delay_time: Optional[int] = None,
                     timer: Timer | int = Timer.TIMER_1) -> list[bytes]:
        return [self.raw(payload) for payload in build_script(
            steps, recipe_id=recipe_id, instruction_index=instruction_index,
            delay_time=delay_time, timer=timer,
        )]

    def stop(self):
        return parse_status(self.raw(build_stop()))

    cancel = stop

    def set_sound(self, enabled: bool):
        return self.raw(build_set_sound(enabled))

    def set_timer(self, timer: Timer | int, minutes: int):
        return self.raw(build_set_timer(timer, minutes))

    def set_timezone(self, zone_id: int, when: Optional[datetime] = None):
        when = when or datetime.now()
        return self.raw(build_timezone(when.year, when.month, when.day, when.hour,
                                       when.minute, when.second, zone_id))

    def close_wifi(self):
        return self.raw(build_close_wifi())


__all__ = ["DiscoveredDevice", "InstantPot", "discover"]
