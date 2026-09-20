"""The inner AA/EC appliance protocol recovered from the APK.

This module deliberately preserves unknown bytes as raw values.  It does not
assign semantics that are absent from the shipped JavaScript sources.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any, Iterable, Mapping, Optional


class CommandType(IntEnum):
    STANDBY = 0
    PREPARING = 1
    DELAYED_EXECUTE = 2
    EXECUTE = 3
    PRESSURE = 4
    HALF_CHANGE = 5
    KEEP_WARM = 6
    SET_SOUND = 7
    SET_TIMER = 8
    SET_DATE = 9


class Preset(IntEnum):
    RICE = 0
    PORRIDGE = 1
    SOUP = 2
    MEAT = 3
    BEAN = 4
    STEAM = 5
    MULTIGRAIN = 6
    SLOW_COOK = 7
    SAUTE = 8
    YOGURT = 9
    MANUAL = 10
    CAKE = 11
    KEEP_WARM = 12
    DIY = 13


class Adjust(IntEnum):
    NORMAL = 0
    MORE = 1
    LESS = 2


class PressureLevel(IntEnum):
    LOW = 0
    HIGH = 1


class KeepWarm(IntEnum):
    OFF = 0
    ON = 1


class Timer(IntEnum):
    TIMER_1 = 0
    TIMER_2 = 1


class SoundState(IntEnum):
    MUTED = 0
    ENABLED = 1


class ScriptOperation(IntEnum):
    HEAT_FOR_PERIOD = 0
    HEAT_TO_TEMPERATURE = 1
    HEAT_TO_PRESSURE = 2
    PAUSE = 3
    HOLD_PRESSURE = 4
    HOLD_TEMPERATURE = 5
    PRESET = 6


LCD_MESSAGES = {
    "done": 0, "add": 1, "yogt": 2, "food": 3, "hot": 4,
    "on": 5, "off": 6, "countup": 7, "countdown": 8,
}
LEDS = {"none": 0, "pressurecook": 1, "keepwarm": 2}
SOUNDS = {"none": 0, "shortbeep": 1, "longbeep": 2,
          "periodicbeep": 3, "music": 4}

HEADER_LENGTH = 18
PRESET_LENGTH = 47
SCRIPT_STEP_LENGTH = 18
MAX_STEPS_PER_COMMAND = 128


def checksum(message: bytes | bytearray | list[int]) -> int:
    """Two's-complement checksum over bytes 1 through the penultimate byte."""
    return (-sum(message[1:-1])) & 0xFF


def _base(length: int, message_type: int = 2, subtype: int = 0) -> bytearray:
    out = bytearray(length)
    out[0] = 0xAA
    out[2] = 0xEC
    out[9] = message_type
    out[10:12] = b"\xAA\x55"
    out[13] = subtype
    return out


def finalize(message: bytearray) -> bytes:
    # The APK stores this in a JavaScript number, then the Cordova bridge
    # narrows it to a Java byte. Large script packets therefore wrap modulo 256.
    message[1] = (len(message) - 1) & 0xFF
    message[-1] = checksum(message)
    return bytes(message)


def validate(message: bytes) -> None:
    if len(message) < 3 or message[0] != 0xAA or message[2] != 0xEC:
        raise ValueError("not an AA/EC Instant Pot message")
    if message[1] != ((len(message) - 1) & 0xFF):
        raise ValueError(f"inner length byte does not match {len(message)} bytes modulo 256")
    if checksum(message) != message[-1]:
        raise ValueError("inner checksum mismatch")


def _set_time(out: bytearray, offset: int, minutes: int) -> None:
    if not 0 <= minutes <= 65535:
        raise ValueError("minutes must be in range 0..65535")
    hours, mins = divmod(minutes, 60)
    if hours > 255:
        raise ValueError("time hours do not fit in the one-byte APK field")
    out[offset:offset + 2] = bytes((hours, mins))


def build_status_query() -> bytes:
    out = _base(21, message_type=3, subtype=3)
    return finalize(out)


def build_time_query() -> bytes:
    out = _base(20, message_type=2, subtype=0x11)
    return finalize(out)


def build_preset(
    preset: Preset | int | str,
    *,
    adjust: Adjust | int | str = Adjust.NORMAL,
    pressure: PressureLevel | int | str = PressureLevel.HIGH,
    cook_time: int = 0,
    pressure_time: Optional[int] = None,
    keep_warm: bool = False,
    delay_time: Optional[int] = None,
    timer: Timer | int = Timer.TIMER_1,
) -> bytes:
    preset = _enum_value(Preset, preset)
    adjust = _enum_value(Adjust, adjust)
    pressure = _enum_value(PressureLevel, pressure)
    timer = _enum_value(Timer, timer)
    out = _base(PRESET_LENGTH, subtype=2)
    out[14] = preset
    out[18] = CommandType.DELAYED_EXECUTE if delay_time is not None else CommandType.EXECUTE
    out[19] = adjust
    out[20] = pressure
    _set_time(out, 25, cook_time)
    _set_time(out, 27, cook_time if pressure_time is None else pressure_time)
    if delay_time is not None:
        _set_time(out, 29, delay_time)
    out[33] = KeepWarm.ON if keep_warm else KeepWarm.OFF
    out[34] = timer
    return finalize(out)


def build_stop() -> bytes:
    out = _base(PRESET_LENGTH, subtype=2)
    out[14] = Preset.RICE  # APK says the value is required; its value is immaterial.
    out[18] = CommandType.STANDBY
    return finalize(out)


def build_set_sound(enabled: bool) -> bytes:
    out = _base(PRESET_LENGTH, subtype=2)
    out[18] = CommandType.SET_SOUND
    out[35] = SoundState.ENABLED if enabled else SoundState.MUTED
    return finalize(out)


def build_set_timer(timer: Timer | int, minutes: int) -> bytes:
    out = _base(PRESET_LENGTH, subtype=2)
    out[18] = CommandType.SET_TIMER
    _set_time(out, 29, minutes)
    out[34] = _enum_value(Timer, timer)
    return finalize(out)


def build_timezone(year: int, month: int, day: int, hour: int, minute: int,
                   second: int, zone_id: int) -> bytes:
    if not 0 <= zone_id <= 0xFFFF:
        raise ValueError("zone_id must be in range 0..65535")
    out = _base(30, subtype=0x60)
    out[18:25] = bytes((year // 100, year % 100, month, day, hour, minute, second))
    out[25:27] = zone_id.to_bytes(2, "little")
    return finalize(out)


def build_close_wifi() -> bytes:
    # This is intentionally unlike normal EC commands: outer type 0x68 and no AA55 body.
    out = bytearray(13)
    out[0] = 0xAA
    out[2] = 0xEC
    out[9] = 0x68
    return finalize(out)


def build_legacy_router_info(ssid: str, password: str) -> bytes:
    """Legacy direct-AP EC 0x21 command; SST provisioning is preferred."""
    ssid_b, password_b = ssid.encode(), password.encode()
    if len(ssid_b) > 255 or len(password_b) > 255:
        raise ValueError("SSID/password is too long")
    out = _base(21 + len(ssid_b) + len(password_b), subtype=0x21)
    out[18] = len(ssid_b)
    out[19:19 + len(ssid_b)] = ssid_b
    pos = 19 + len(ssid_b)
    out[pos] = len(password_b)
    out[pos + 1:pos + 1 + len(password_b)] = password_b
    return finalize(out)


def build_legacy_wifi_to_sta() -> bytes:
    out = _base(20, subtype=0x22)
    return finalize(out)


@dataclass
class ScriptStep:
    operation: ScriptOperation | int | str
    message: int | str = 0
    led: int | str = 0
    sound: int | str = 0
    heat_to_temperature: int = 0
    heat_to_pressure: PressureLevel | int | str = PressureLevel.LOW
    duration: int = 0
    hold_temperature: int = 0
    hold_pressure: PressureLevel | int | str = PressureLevel.LOW
    heat_level: int = 0
    preset: Preset | int | str = Preset.RICE
    adjust: Adjust | int | str = Adjust.NORMAL


def _mapped(value: int | str, mapping: Mapping[str, int]) -> int:
    if isinstance(value, str):
        key = value.replace("_", "").replace("-", "").lower()
        normalized = {k.replace("_", "").replace("-", "").lower(): v
                      for k, v in mapping.items()}
        if key not in normalized:
            raise ValueError(f"unknown value {value!r}; choose from {sorted(mapping)}")
        return normalized[key]
    return int(value)


def _enum_value(cls: type[IntEnum], value: IntEnum | int | str) -> int:
    if isinstance(value, str):
        key = value.replace("-", "_").replace(" ", "_").upper()
        aliases = {"SLOWCOOK": "SLOW_COOK", "KEEPWARM": "KEEP_WARM",
                   "TIMER1": "TIMER_1", "TIMER2": "TIMER_2"}
        key = aliases.get(key.replace("_", ""), key)
        try:
            return int(cls[key])
        except KeyError as exc:
            raise ValueError(f"unknown {cls.__name__} {value!r}") from exc
    return int(cls(value))


def _script_step(step: ScriptStep, index: int) -> bytes:
    out = bytearray(SCRIPT_STEP_LENGTH)
    out[0] = index
    out[1] = _enum_value(ScriptOperation, step.operation)
    out[2] = _mapped(step.message, LCD_MESSAGES)
    out[3] = _mapped(step.led, LEDS)
    out[4] = _mapped(step.sound, SOUNDS)
    out[5] = step.heat_to_temperature
    out[6] = _enum_value(PressureLevel, step.heat_to_pressure)
    _set_time(out, 7, step.duration)
    out[9] = step.hold_temperature
    out[10] = _enum_value(PressureLevel, step.hold_pressure)
    out[11] = step.heat_level
    out[12] = _enum_value(Preset, step.preset)
    out[13] = _enum_value(Adjust, step.adjust)
    return bytes(out)


def build_script(
    steps: Iterable[ScriptStep], *, recipe_id: int = 0, instruction_index: int = 0,
    delay_time: Optional[int] = None, timer: Timer | int = Timer.TIMER_1,
) -> list[bytes]:
    steps = list(steps)
    dummy = bytearray(SCRIPT_STEP_LENGTH)
    if delay_time is not None:
        dummy[14] = 1
        dummy[15] = _enum_value(Timer, timer)
        _set_time(dummy, 16, delay_time)
    bodies = [bytes(dummy)] + [_script_step(step, i + 1) for i, step in enumerate(steps)]
    if len(bodies) > 255:
        raise ValueError("APK script count and step index fields are one byte (maximum 255)")
    commands = []
    for start in range(0, len(bodies), MAX_STEPS_PER_COMMAND):
        group = bodies[start:start + MAX_STEPS_PER_COMMAND]
        out = _base(HEADER_LENGTH + 5 + len(group) * SCRIPT_STEP_LENGTH + 1,
                    subtype=0x20)
        out[14] = instruction_index & 0xFF
        out[15:18] = recipe_id.to_bytes(3, "little")
        out[18:20] = b"\x00\x00"  # APK calls this a random field but always writes zero.
        out[20] = 2                 # Explicitly unknown in the APK source.
        out[21] = len(bodies)
        out[22] = SCRIPT_STEP_LENGTH
        pos = 23
        for body in group:
            out[pos:pos + SCRIPT_STEP_LENGTH] = body
            pos += SCRIPT_STEP_LENGTH
        commands.append(finalize(out))
    return commands


def _name(enum: type[IntEnum], value: int) -> str:
    try:
        return enum(value).name.lower()
    except ValueError:
        return f"unknown_{value}"


def _time(data: bytes, offset: int) -> int:
    return data[offset] * 60 + data[offset + 1]


@dataclass
class DiyStatus:
    num_steps: int = 0
    step_index: int = 0
    operation: str = "unknown"
    message: str = "unknown"
    led: str = "unknown"
    sound: str = "unknown"
    heat_to_temperature: int = 0
    heat_to_pressure: str = "unknown"
    duration: int = 0
    hold_temperature: int = 0
    hold_pressure: str = "unknown"
    heat_level: int = 0
    preset: str = "unknown"
    adjust: str = "unknown"


@dataclass
class PotStatus:
    preset: str
    recipe_id: int
    instruction_index: int
    command_type: str
    error_code: str
    delay_time: int
    cook_time: int
    pressure_time: int
    warm_time: int
    adjust: str
    pressure: str
    is_pressure: int
    above_temp: int
    below_temp: int
    is_balance_temp: bool
    lid_is_open: bool
    is_yogurt_done: bool
    is_burning: bool
    is_saute_heating: bool
    is_muted: bool
    is_pressure_2: bool
    is_definitely_no_pressure: bool
    unknown_34_39: list[int]
    timer1: int
    timer2: int
    diy: DiyStatus
    started_by_app: Optional[int]
    push_key: Optional[int]
    raw_hex: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


ERRORS = {
    0: "no_error", 1: "bottom_temperature_sensor_disconnected",
    2: "bottom_temperature_sensor_short", 3: "bottom_over_temperature",
    4: "pressure_switch_fault",
}


def parse_status(data: bytes) -> PotStatus:
    validate(data)
    if len(data) < 59:
        raise ValueError(f"status needs at least 59 bytes, got {len(data)}")
    recipe_id = int.from_bytes(data[15:18], "little")
    preset = "diy" if recipe_id else _name(Preset, data[14])
    flags = data[33]
    diy = DiyStatus(
        num_steps=min(MAX_STEPS_PER_COMMAND, max(0, data[44] - 1)),
        step_index=data[45], operation=_name(ScriptOperation, data[46]),
        message=_reverse(LCD_MESSAGES, data[47]), led=_reverse(LEDS, data[48]),
        sound=_reverse(SOUNDS, data[49]), heat_to_temperature=data[50],
        heat_to_pressure=_name(PressureLevel, data[51]), duration=_time(data, 52),
        hold_temperature=data[54], hold_pressure=_name(PressureLevel, data[55]),
        heat_level=data[56], preset=_name(Preset, data[57]),
        adjust=_name(Adjust, data[58]),
    )
    return PotStatus(
        preset=preset, recipe_id=recipe_id, instruction_index=data[14],
        command_type=_name(CommandType, data[18]),
        error_code=ERRORS.get(data[19], f"unknown_{data[19]}"),
        delay_time=_time(data, 20), cook_time=_time(data, 22),
        pressure_time=_time(data, 24), warm_time=_time(data, 26),
        adjust=_name(Adjust, data[28]), pressure=_name(PressureLevel, data[29]),
        is_pressure=data[30], above_temp=data[31], below_temp=data[32],
        is_balance_temp=bool(flags & 1), lid_is_open=bool(flags & 2),
        is_yogurt_done=bool(flags & 4), is_burning=bool(flags & 8),
        is_saute_heating=bool(flags & 16), is_muted=not bool(flags & 32),
        is_pressure_2=bool(flags & 64), is_definitely_no_pressure=bool(flags & 128),
        unknown_34_39=list(data[34:40]), timer1=_time(data, 40), timer2=_time(data, 42),
        diy=diy, started_by_app=data[59] if len(data) >= 62 else None,
        push_key=data[60] if len(data) >= 62 else None, raw_hex=data.hex().upper(),
    )


def _reverse(mapping: Mapping[str, int], value: int) -> str:
    return next((name for name, number in mapping.items() if number == value),
                f"unknown_{value}")


def parse_time_info(data: bytes) -> dict[str, int | str]:
    validate(data)
    if len(data) < 26:
        raise ValueError("time-info response is too short")
    return {
        "factory_year": data[18], "factory_month": data[19],
        "factory_day": data[20], "zone_id": int.from_bytes(data[21:23], "little"),
        "hour": data[23], "minute": data[24],
        "second": data[25], "raw_hex": data.hex().upper(),
    }
