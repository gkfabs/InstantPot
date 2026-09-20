# instantpot-local

This repository now contains a cloud-free Python library and CLI for the 2018
Instant Pot Smart WiFi (Midea appliance family `0xEC`). It uses only the local
network. It does not use Android, Cordova, a Midea account, or an Instant Pot
account.

The implementation is based on code shipped inside the supplied APK. The full
evidence and feature inventory are in
[docs/APK_PROTOCOL_INVENTORY.md](docs/APK_PROTOCOL_INVENTORY.md).

## Reverse-engineering process

The work started from the supplied 2018 Android APK. The unpacked application
is in `remote_control_for_smart_wifi/`. The analysis traced each user action
from the Cordova JavaScript service into the Java bridge and Midea SDK code.

The JavaScript builders established the inner `AA/EC` command types, field
offsets, and enumerated values. The decompiled Java and smali code established
UDP discovery, TCP connections, SST framing, authentication, encryption, and
response parsing. The existing working SST provisioner supplied the known-good
provisioning cryptography.

Live tests then compared the implementation with the cooker. These tests
validated factory reset, provisioning, discovery, protocol 3 authentication,
and status queries. One live failure exposed a protocol 3 envelope error. The
APK showed that the SHA-256 value covers the six-byte header and padded
plaintext, not the ciphertext. The corrected implementation then returned the
cooker status through the home network.

The implementation assigns a meaning only when APK code or a live result
establishes it. Unknown bytes remain raw values. The inventory cites the exact
JavaScript, Java, or smali evidence and states the confidence for each feature.

## Safety

Cooking commands can energize the heater. Keep the cooker attended while you
validate this implementation. `close-wifi` disables the cooker's Wi-Fi and
requires `--yes`. The library does not guess unsupported commands. In
particular, the APK's standalone `pressure()` command is a stub, so the CLI
only exposes pressure as a documented preset or DIY-script field.

## Provisioning

### Factory reset

Use this procedure to erase the previous Wi-Fi registration and Secret Key.

1. Put the cooker in standby mode.
2. Press and hold the `Pressure Level` button that has the Wi-Fi symbol.
3. Keep holding the button after the cooker enters its three-second setup mode.
4. Release the button after at least ten seconds.
5. Wait for the `Instant_Pot_*` setup network to appear.

A three-second press only starts setup mode. It does not erase the previous
registration. After a factory reset, provisioning response `0x8075/0000`
shows that the cooker accepted a new Secret Key. Response `0x8075/0001` shows
that the cooker retained and verified an existing Secret Key.

Connect the computer to the `Instant_Pot_*` setup network. Then run the exact
already-validated SST implementation:

```bash
mise run instantpot -- provision \
  --ssid <WIFI_SSID>
```

The CLI prompts for the Instant Pot secret and Wi-Fi password without printing
them.

Response `0x8075/0000` means that the cooker accepted a new Secret Key.
Response `0x8075/0001` means that it verified an existing Secret Key. Response
`0x8075/0002` means that verification failed. The APK parser and callback
establish these meanings.

The unified CLI stores only the derived local key after successful Wi-Fi
configuration. It stores the key in
`~/.config/instantpot-local/credentials.json` with mode `0600`. Use
`--no-save-credentials` if you do not want this file.

## Local use

Install the declared tools and synchronize the project environment:

```bash
mise install
mise run sync
```

Run all CLI commands through the `instantpot` task:

```bash
mise run instantpot -- discover
mise run instantpot -- status --host 192.168.4.55
mise run instantpot -- preset --host 192.168.4.55 manual \
  --cook-time 10 --pressure-time 10 --pressure high --keep-warm
mise run instantpot -- stop --host 192.168.4.55
mise run instantpot -- sound --host 192.168.4.55 mute
mise run instantpot -- timer --host 192.168.4.55 1 450
mise run instantpot -- time-info --host 192.168.4.55
```

### Cooker clock and time zone

Read the cooker clock and numeric time-zone ID:

```bash
mise run instantpot -- time-info --host 192.168.4.124
```

The `factory_year`, `factory_month`, and `factory_day` fields contain the
manufacturing date. The `hour`, `minute`, and `second` fields contain the
cooker clock.

The APK uses numeric time-zone IDs. The `timezone` command sends the current
computer date and time with one of these IDs:

```bash
mise run instantpot -- timezone --host 192.168.4.124 ZONE_ID
```

Make sure that the computer clock is correct before you send this command.
Read `time-info` again after the command to see the result.

On the tested cooker, time-zone ID `161` identified `America/Mexico_City`.
The cooker showed a time that was one hour ahead of the computer. Changing the
ID to `190`, which the APK assigns to `America/Regina`, stored the new ID but
did not change the hour or the front-panel clock. This live result shows that
the command can store the time-zone ID. It does not establish that this
firmware can change the front-panel clock through the network command.

Set the front-panel clock manually:

1. Put the cooker in standby mode.
2. Press and hold `Delay Start` for 10 seconds until the cooker beeps.
3. Use `+` and `-` while the clock flashes.
4. Press `Pressure Level` to select the hour or minute field.
5. Press and hold `Delay Start` for 3 seconds to save the time.

These steps come from the
[Instant Pot Smart WiFi manual](https://manuals.plus/wp-content/sideloads/instant-pot-smart-wifi-manual-optimized.pdf).

Discovery supplies the six-byte device ID automatically. Use
`--device-id DECIMAL_ID` if discovery is blocked across a subnet or VLAN.

Protocol version 3 cookers require local TCP authentication. The APK supplies
two paths. An unregistered cooker can use bootstrap authentication. Supply the
home Wi-Fi SSID with `--ssid` for the first successful connection if you used
the standalone provisioner. The CLI requests the Wi-Fi password through a
hidden prompt. It stores the derived key, not the password. Later commands load
the key by cooker MAC address. The local key uses the exact APK algorithm:
`SHA-256(SSID || password || cooker MAC)`. It uses the raw digest as the
32-byte AES key. Discovery supplies the cooker MAC address automatically.

A registered cooker can reject bootstrap authentication with `ERROR`. It then
requires the 64-byte LAN token and AES key assigned during registration. Supply
an existing pair with `--token` and `--key`. The APK obtains this pair from a
cloud response. The APK does not contain a local algorithm that derives it.

### Internet access can change the authentication state

WAN access means access from the local network to the internet. A live test
showed that WAN access can move the cooker from bootstrap mode to registered
mode. The user did not create an account on the test tablet.

Before WAN access, discovery reported `device_id: 0` and supplied a
`random_code`. After WAN access, discovery reported these values:

```text
configured: true
device_id: 151732607748927
random_code: null
secret_key_exists: true
```

The next local query failed before it sent the appliance command:

```text
instantpot-local: protocol 3 key agreement rejected: ERROR; bootstrap authentication failed; a recovered --token and --key pair can use the other APK path
```

These results show that the cooker stored a registered authentication state.
They do not identify the internet service that supplied the state. Registered
mode requires the assigned LAN token and AES key. Blocking WAN access after
registration does not clear these stored credentials.

If you want to keep bootstrap authentication, block WAN access before you
provision the cooker. Keep local TCP port 6444 and UDP port 6445 available.
Keep WAN access blocked after provisioning.

If the cooker enters registered mode, restore bootstrap mode as follows:

1. Block WAN access for the cooker.
2. Use the [factory reset procedure](#factory-reset) above.
3. Connect the computer to the `Instant_Pot_*` setup network.
4. Provision the cooker again.
5. Reconnect the computer to the home Wi-Fi network.
6. Run `discover`, then run the required local command.

The APK also supports direct control on the cooker setup network. Hold the
Wi-Fi button for 3 seconds, then connect the computer to `Instant_Pot_*`. Query
status with the following command:

```bash
mise run instantpot -- status --host 192.168.1.1 --direct-ap
```

The CLI asks for the Instant Pot Secret Key. It sends the APK hello and secret
verification transaction on the same TCP connection before the status query.

If discovery is unavailable, supply all transport fields explicitly:

```bash
mise run instantpot -- status \
  --host 192.168.4.124 \
  --device-id 151732607748927 \
  --protocol 3 \
  --mac f0:c9:d1:7d:65:14 \
  --ssid <WIFI_SSID>
```

The bootstrap path does not contact either cloud. It does not bypass a token
that the cooker already accepted during registration.

DIY scripts use the APK field names. Values such as temperature and heat level
are intentionally raw integers because the APK source does not establish a
unit or scaling rule:

```json
{
  "steps": [
    {
      "operation": "heat_to_temperature",
      "message": "countdown",
      "heat_to_temperature": 80,
      "duration": 15,
      "sound": "shortbeep"
    }
  ]
}
```

```bash
mise run instantpot -- script --host 192.168.4.55 steps.json
```

Run the protocol tests and SST self-test with:

```bash
mise run test
```
