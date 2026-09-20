# 2018 Instant Pot Smart WiFi APK protocol inventory

## Scope and evidence notation

This inventory covers code that communicates with the cooker. Account login,
device sharing, push notifications, remote OTA orchestration, device naming,
and other server-only features are identified but not reproduced.

Evidence paths below are relative to `remote_control_for_smart_wifi/instantpot-final`.
For source-map evidence, the first path is the physical map and the path after
`sourcesContent:` is the original virtual source embedded in it.

Confidence means:

- **High**: an exact builder/parser and the native transport call are present.
- **Medium**: framing is exact, but a field meaning or response behavior is not
  fully established by the APK.
- **Not implemented by APK**: the public API exists but the shipped method is a stub.

## Transport stack

The cooker command is an inner `AA/EC` message carried inside an SST `5A5A`
frame:

1. UDP/6445 discovers the device. `com/midea/iot/sdk/aE.smali`, method
   `a([BLjava/net/InetAddress;)`, fixes destination port `0x192D` (6445).
2. Local control uses TCP/6444. The successful supplied pairing capture also
   shows the cooker at TCP/6444 and UDP/6445.
3. `com/midea/iot/sdk/db.smali`, synthetic method
   `a(db,String,[B)`, logs “Send device … data by lan” and creates `bc` with
   request `0x0020` and response `0x8020`.
4. `com/midea/iot/sdk/aZ$a.smali`, method `a()`, passes the appliance payload,
   IDs, six-byte device ID, signature flag, and encryption flag to
   `V.a([BSILjava/lang/String;ZZ)` and writes the result to the socket.
5. `com/midea/iot/sdk/V.smali`, methods
   `a([BSILjava/lang/String;ZZ)`, `c()`, and `a([B)`, establish the `5A5A`
   layout, little-endian fields, encryption, signature, and parsing.
6. `com/midea/iot/sdk/bj.smali` calls native `eaes32WithoutKey` and
   `emd5WithoutKey`. The already validated `instantpot_local/sst.py`
   implements these as AES-128-ECB with PKCS#7 using
   `MD5("xhdiwjnchekd4d512chdjx5d8e4c394D2D7S")`, plus
   `MD5(frame_without_digest || same_constant)`.

The library reuses the validated SST functions directly. Control sets outer
command `0x0020`; the expected response is `0x8020`. The six-byte device ID is
the low 48 bits of the decimal ID in little-endian order, exactly as
`fI.c(String)` and `V.a(...)` construct it.

### Inner AA/EC common header

| Offset | Meaning | Evidence |
|---:|---|---|
| 0 | `AA` | `MessageBuilderService.setFixedHeaderBytes` |
| 1 | total length minus one | `MessageBuilderService.finalizeMessage` |
| 2 | appliance family `EC` | `setFixedHeaderBytes` |
| 3–8 | zero in all app builders | exact builders |
| 9 | message type: `02` app, `03` query, or special `68` | exact builders |
| 10–11 | `AA 55`, except close-Wi-Fi | `setFixedHeaderBytes`, `getCloseWifiData` |
| 12 | zero | exact builders |
| 13 | subtype/command ID | exact builders |
| 14–17 | preset or script identity, depending on subtype | builder and parser |
| 18… | command-specific body | builder and parser |
| last | two's-complement checksum of offsets 1 through last-1 | `calCheckSum` and `MessageBuilderService.checksum` |

Primary JavaScript evidence:

- `assets/www/plugins/ionic-plugins-msmart/www/MSmart.js`, lines 2190–2771.
- `assets/www/build/vendor.js.map`, `sourcesContent:`
  `instant-pot-manager/dist/src/wifi/message-builder.service.js.pre-build-optimizer.js`.
- Same map, `message-parser.service.js.pre-build-optimizer.js`,
  `wifipot.constants.js`, `model-to-wifi-maps.js`, and
  `services/msmart-api.service.js.pre-build-optimizer.js`.

## Feature inventory

| User-visible feature | JavaScript/Cordova entry point | Native Java/SDK implementation | Request → response IDs | Packet/payload | Transport and security | Known response/status fields | Confidence/evidence |
|---|---|---|---|---|---|---|---|
| Find cooker on LAN | `MSmart.findDeviceInLanWithTimeout(interval)`; app `DevicesService.refresh()` | `MSmart$38.run` → `MSmartUserDeviceManager.scanLanDevice`; SDK `bM.scanLanDevice`; `bq.a(DatagramPacket)` unwraps protocol 3 | Discovery `0x0092` in the supplied 72-byte probe; response is `5A5A` or an `8370` wrapper around `5A5A` | Standard 72-byte Midea discovery datagram; response header contains six-byte device ID; decrypted body contains serial, SSID, MAC, and a 16-byte provisioning field | UDP/6445; discovery body AES-128-ECB with key `6a92ef406bad2f0359baad994171ea6d`; protocol 3 adds an `8370` integrity wrapper | IP, device ID, serial, SSID, MAC, protocol version; appliance family is corroborated by serial prefix `0000EC` | High. Live response from the supplied cooker confirms protocol 3 and MAC `f0:c9:d1:7d:65:14` |
| Query current SoftAP device | `queryCurDevice()` | `MSmart$15.run` → SDK `queryCurDevice` | SDK internal | Returns local device metadata, not pot state | Local SDK discovery/state | `deviceId`, `deviceSn`, `deviceSsid`, `deviceType`, `deviceSubType`, activation and secret flags (see `wifipot.js`) | High; local setup only |
| Connect to current SoftAP device | `connectCurDevice(secretKey)` | `MSmart$19$1.run` → `connectCurDevice`; SDK `bM` → `cu.a(secret,callback)` | SST connect/setup exchange; exact internal IDs vary by step | Secret is passed to the direct-device connector | TCP/6444, SST signed/encrypted after connection | success/error only | High that it is local and secret-authenticated; individual connection-state packet semantics are not reimplemented because validated SST provisioning bypasses this SDK state machine |
| Send to current directly connected device | `sendDataToCurDevice(data)` | `MSmart$23.run` → `sendDataToDirectDevice`; SDK `bM.sendDataToDirectDevice` builds outer `0x20/0x8020` | `0x0020 → 0x8020`, inner ID varies | Arbitrary byte array, normally complete `AA/EC` | Direct TCP connection, SST AES/signature | byte-array response | High |
| Send by device ID | `sendDataWithDeviceId(deviceId,data)`; all normal cooking APIs use it | `MSmart$58.run` → `sendDeviceData`; `bM.sendDeviceData` selects registered LAN/WAN object; `db` uses LAN when present; `bm.a` selects protocol 2 or 3 | local `0x0020 → 0x8020`; WAN server path is separate | Arbitrary complete `AA/EC` payload | LAN: TCP/6444 SST. Protocol 3 uses the authenticated `8370` envelope. The replacement omits the WAN route | `{code,hexCmdArray,deviceId}` | High. Live testing confirms that this cooker closes TCP after an unwrapped protocol 2 command |
| Status query (`getPotStatue`, spelling retained) | Cordova `getPotStatue()` builds `getPotStatueData`; app uses `builder.makeGetInfoCommand()` via `MSmartApiService.info()` | `MSmart$54` selects direct for ID `-1`, otherwise `sendDeviceData`; callback returns raw bytes | inner type `03`, subtype `03`; outer `0x20 → 0x8020` | Exact 21-byte request: `AA 14 EC 00 00 00 00 00 00 03 AA 55 00 03 00 00 00 00 00 00 FB` | Local TCP as above | See detailed status table below | High |
| Start preset/program | `CommandsService…preset`; `MSmartApiService.preset`; UI `InstantStartCookPage.start` | Generic `MSmart$58` → SDK send | inner type `02`, subtype `02`; command type byte 18 = `03` execute or `02` delayed execute | 47 bytes. preset byte 14; adjust 19; pressure 20; cook time 25–26; pressure time 27–28; delay 29–30; Keep Warm 33; timer 34 | Local TCP SST | Returns a status-shaped payload parsed by `parseCommandResult` | High |
| Programs | Same as prior row | Same | subtype `02` | byte 14: rice 0, porridge 1, soup 2, meat 3, bean 4, steam 5, multigrain 6, slow cook 7, sauté 8, yogurt 9, manual/pressure cook 10, cake 11, keep warm 12, DIY 13 | Same | status `preset` | High; constants source |
| Adjust Less/Normal/More | Preset options in `InstantStartCookPage`; `MSmartApiService.preset` | Generic send | subtype `02` | byte 19: Normal 0, More 1, Less 2 | Same | status byte 28 | High |
| Pressure level | Preset option and DIY fields | Generic send | subtype `02` or `20` | preset byte 20: low 0/high 1; DIY heat/hold pressure bytes documented below | Same | status byte 29; DIY bytes 51/55 | High. Separate `MSmartApiService.pressure()` is a no-op stub and is not exposed |
| Cook/pressure/delay time | Preset options | Generic send | subtype `02` | each is `[hours, minutes]`: cook 25–26, pressure 27–28, delay 29–30 | Same | status delay 20–21, cook 22–23, pressure 24–25, warm 26–27 | High |
| Keep Warm | Preset option `keepWarm`; keep-warm is also preset 12 and DIY LED 2 | Generic send | subtype `02` | preset byte 33: off 0/on 1 | Same | command type `06` means Keep Warm; status service also treats execute+preset 12 as Keep Warm | High |
| Start with stored timer / scheduling | UI `delayStart`, `delayTime`, `useTimer2`; preset and script builders | Generic send | preset subtype `02`; script subtype `20` | preset byte 18=`02`, delay at 29–30, timer at 34; script dummy step bytes 14 enable, 15 timer, 16–17 time | Same | `DelayedExecute`, delay minutes, selected timer inferred by equality to timer1 | High |
| Stop/cancel | `DeviceStatusPage.stop`, `InstructionStatus.stop`; `MSmartApiService.stop`; legacy `MSmart.stopCook` | generic send or `MSmart$56` | subtype `02`, command type `00` | 47-byte blank preset command; byte 14 explicitly set to rice 0 because a value is required; byte 18 Standby 0 | Same | returned status; Standby means stopped/idle | High |
| Sound/mute | Settings page `setSoundState`; Cordova `setPotMute` | generic send; legacy `MSmart$52` | subtype `02`, command type `07` | 47 bytes; byte 35 muted 0/enabled 1. Legacy `openMute=true` writes 0 | Same | status work-icon byte 33 bit 5, inverted: clear means muted; legacy getter returns `mute` from byte 33 | High |
| Stored timer 1/2 | Settings page `onSaveTimer`; Cordova `setPotTimer` | generic send; legacy `MSmart$53` | subtype `02`, command type `08` | time at bytes 29–30; timer selector byte 34 (0/1) | Same | timers at status bytes 40–41 and 42–43 | High |
| Factory date, cooker clock, timezone ID | `getPotProductionDate`, `getPotTime`, `getPotZoneid`; app settings | `MSmart$46/$47/$51` | type `02`, subtype `11` | 20-byte query | Same | date bytes 18–20 (YY/M/D), zone ID little-endian 21–22, time 23–25 | High |
| Synchronize date/time/timezone | `asynTimeZone(deviceId,zoneIdentify)` → `getAsyntimeData` | `MSmart$43` | type `02`, subtype `60` | 30 bytes; bytes 18–24 CC,YY,M,D,h,m,s; bytes 25–26 numeric timezone ID little-endian | Same | Live response includes the stored zone ID and cooker hour. Other response fields are not fully established. | High for the request format. Live tests changed zone ID from 161 to 190, but neither the reported hour nor the front-panel clock changed. Use the documented front-panel procedure to set the visible clock. |
| DIY recipe/script | `RecipeExecutionService.start`; `MSmartApiService.script`; `MessageBuilderService.buildScriptCommands` | generic send | type `02`, subtype `20` | header bytes 14 instruction, 15–17 recipe ID LE, 18–19 zero “random”, 20 unknown constant 2, 21 step count including dummy delay step, 22 step length 18; then steps | Same | current step/status bytes 44–58 | High except byte 20 semantics and temperature/heat-level units, which remain explicitly unknown |
| DIY heat/time/temperature controls | `ScriptStep` and `makeStepBody` | generic send | script subtype `20` | each 18-byte step: index 0; operation 1; LCD 2; LED 3; sound 4; heat target 5; pressure target 6; duration 7–8; hold temperature 9; hold pressure 10; heat level 11; preset 12; adjust 13 | Same | mirrored in status bytes 45–58 | High for offsets/enums; **units/scaling for bytes 5, 9, and 11 are not established** |
| Legacy send router credentials | `sendRouterInfo(ssid,password)` → `getRouterData` | `MSmart$45` → direct device | type `02`, subtype `21` | SSID length+bytes, password length+bytes | Direct SoftAP TCP SST | success/error | High, but superseded by the validated SST `0x0075/0x0070` flow and not used by the CLI |
| Legacy switch SoftAP to station | `WiFiToSTA()` → `getWiFiStaData` | `MSmart$48` → direct device | type `02`, subtype `22` | 20-byte command | Direct SoftAP TCP SST | callback validates response length/content | High, but not used; validated SST Wi-Fi write already switches mode |
| Disable/close Wi-Fi | `closeWifi(deviceId)` → `getCloseWifiData` | `MSmart$55`; response checks byte 11 | inner message type `68`, no normal subtype | 13 bytes: `AA 0C EC 00 00 00 00 00 00 68 00 00 checksum` | Direct or LAN/WAN-selected SDK path; local replacement uses TCP | response byte 11: zero success; response shorter than 13 is failure | High; destructive and CLI requires `--yes` |
| OTA check/apply | `queryDeviceOTAState`, `startDeviceOTAState` | server SDK methods | not an EC cooker command in the app | server-provided version/update operations | Cloud | version/update lists and push result | Cloud-only; intentionally omitted |
| Rename/share/unshare/account/push | corresponding `MSmart` methods | server manager SDK | not EC cooker commands | JSON/server calls | Cloud | account/device metadata | Cloud-only; intentionally omitted |

## Status response fields

Evidence is `MessageParserService.parsePotStatus`,
`parseDiyStatus`, and `parseWorkIcon` in the embedded vendor source map. The
older specialized Cordova callbacks independently corroborate mute, timers,
timezone, date, and clock offsets.

| Offset | Field |
|---:|---|
| 14 | preset ID, or recipe instruction index when bytes 15–17 are nonzero |
| 15–17 | recipe ID, little-endian; nonzero means DIY |
| 18 | command type: Standby 0, Preparing 1, DelayedExecute 2, Execute 3, Pressure 4, HalfChange 5, KeepWarm 6, SetSound 7, SetTimer 8, SetDate 9 |
| 19 | error: 0 none, 1 bottom sensor disconnected, 2 bottom sensor short, 3 bottom over-temperature, 4 pressure-switch fault |
| 20–21 | delay time `[hours,minutes]` |
| 22–23 | cook time |
| 24–25 | pressure time |
| 26–27 | warm time |
| 28 | adjust |
| 29 | pressure level |
| 30 | `isPressure` raw byte; exact boolean semantics are not further established |
| 31 | `aboveTemp` raw byte |
| 32 | `belowTemp` raw byte; UI uses this as temperature, but unit/scaling is not established in the parser |
| 33 bits 0–7 | balance temperature, lid open, yogurt done, burning, sauté heating, sound enabled (inverted to `isMuted`), second pressure flag, definitely-no-pressure |
| 34–39 | unknown; preserved raw |
| 40–41 | timer 1 |
| 42–43 | timer 2 |
| 44 | DIY step count including the dummy step; app reports `max(0,value-1)` |
| 45 | current DIY step index |
| 46–58 | operation, LCD, LED, sound, heat target, pressure target, duration, hold temperature, hold pressure, heat level, preset, adjust |
| 59–60 | optional `startedByApp`, `pushKey` in 62-byte format |
| last | checksum |

The APK contains comments that bytes previously labeled `pressSwitch` and
`isHeated` were not understood. The replacement returns no guessed versions of
those fields.

## Provisioning

Provisioning is not an EC `0x21/0x22` control transaction in the successful
capture. The validated process in `instantpot_local/sst.py` is retained:

| Step | Outer SST ID | Payload | Security |
|---|---:|---|---|
| hello | `0x007B` | one zero byte | signed, not encrypted |
| set/verify secret | `0x0075 → 0x8075` (an intermediate `0x8076` can occur) | seven zeros, one-byte secret length, UTF-8 alphanumeric secret | AES + signature |
| write Wi-Fi configuration | `0x0070 → 0x8070` | random ASCII 16 bytes, SSID length/data, password length/data, optional BSSID length/data | AES + signature |

This is why the new CLI delegates provisioning to the existing implementation
instead of rebuilding or substituting the obsolete Cordova helper.

## Protocol 3 local TCP authentication

The supplied cooker answers discovery with an `8370` protocol 3 wrapper. It
closes TCP when a client sends an unwrapped protocol 2 control frame.

The APK contains two protocol 3 key-agreement paths. The normal registered
device path uses a token and key from the cloud response. The local setup path
does not require the cloud. `bs.a(String,String,byte[])` hashes the home SSID,
the Wi-Fi password, and the six raw MAC bytes with SHA-256. It uses the full
32-byte digest as the bootstrap AES key.

`bt.a(by,bv,bm)` generates a 32-byte client random value. `bs.a(byte[],String)`
encrypts that value with AES-CBC and a zero IV. It sends this value in an
`83 70 00 40 20 00 00 00` key-agreement packet with its SHA-256 digest. The
device returns a 32-byte value encrypted by the client random value. `bq.a`
makes sure that the response digest is correct. It XORs both 32-byte values to
form the TCP session key.

`aB.a(byte[])` supplies the exact data envelope. It prepends a two-byte counter
to the complete `5A5A` frame and pads that plaintext to an AES block. It appends
SHA-256 over the six-byte header and padded plaintext, but transmits the
plaintext encrypted with AES-CBC and a zero IV. This order differs from newer
Midea implementations that hash the ciphertext. The request packet type is 6.
`bq.a` accepts response packet type 3, decrypts before verifying the digest,
removes the counter and padding, and passes the inner `5A5A` frame to the
normal parser.

After the attempted reset, discovery reports device ID zero and a new 16-byte
random code. These fields occur during setup. They do not prove that the cooker
cleared its old LAN registration. The cooker still rejects the exact APK
bootstrap request with `ERROR`.

The provisioning response parser `aU.a(V)` reads payload byte 1. Callbacks
`dG.a(bd)` and `cI.a(bd)` treat only value `2` as secret verification failure.
Thus, `0x8075/0000` accepts a new secret, and `0x8075/0001` verifies an existing
secret. The earlier provisioner incorrectly treated `0001` as uncertain.

The current cooker still returns an `8370` `ERROR` for the exact bootstrap
request. The saved key also matches the key derived from the original pairing
log. This result rules out an SSID, password, MAC, and key-derivation mismatch.
The remaining supported APK path uses the registered 64-byte token and AES key.

The CLI stores the 32-byte bootstrap key by cooker MAC address. The file is
`~/.config/instantpot-local/credentials.json`, and its mode is `0600`. The file
does not contain the Wi-Fi password. The unified provision command writes this
file unless the user supplies `--no-save-credentials`.

## Implementation coverage

- `instantpot_local/protocol.py`: exact inner message builders and status parser.
- `instantpot_local/transport.py`: UDP discovery, protocol 2 SST, and authenticated protocol 3 TCP.
- `instantpot_local/client.py`: high-level local API.
- `instantpot_local/cli.py`: discovery, provisioning, status, preset, script,
  stop, mute, timers, time, timezone, raw command, and guarded Wi-Fi disable.
- `instantpot_local/credentials.py`: private storage for derived local keys.
- `tests/test_protocol.py`: deterministic byte-offset, checksum, script, key-derivation,
  and transport-envelope tests. Tests send nothing over the network.
