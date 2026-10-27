# rowxplorer-lib

Control **Rowenta X-Plorer 45** robot vacuums (and other Groupe SEB robots on
the same platform) from Python, over the SEB cloud.

> **Disclaimer** — This library is provided for personal use with your own
> robot and account. Use at your own risk; it is not affiliated with or
> endorsed by Groupe SEB / Rowenta.

## How it works

The robot is controlled through the SEB IoT cloud:

1. **OAuth** — you sign in with your SEB/Rowenta account. This yields a
   long-lived `refresh_token` (the only secret you need to store) plus
   short-lived tokens (`access_token` / `id_token`, ~120 s) minted on demand.
2. **Cognito** — the `id_token` is exchanged for temporary AWS IAM credentials.
3. **MQTT over WSS** — the IAM credentials sign a WebSocket connection (SigV4)
   to the AWS IoT endpoint; status and commands are exchanged as MQTT messages.

Everything except the `refresh_token` is minted and cached in memory at
runtime — nothing is written to disk.

## Device discovery

The robot's UUID (the `ROBOT_ID` used in the MQTT topics) is not something you
type by hand. The library lists the robots paired with your SEB account, read
from the account's SEB profile:

```python
from rowxplorer_lib import RowxplorerClient

client = RowxplorerClient.seb()  # needs IOT_REFRESH_TOKEN
for dev in client.list_devices():
    print(dev.name, dev.uuid, dev.thing_type)
```

```bash
rowxplorer-lib --seb devices
```

Each device's `uuid` is the `ROBOT_ID` you configure, and `thing_type` is the
`PRODUCT_ID`. Accounts with several robots can target one of them — see
[Multi-robot](#multi-robot).

> The profile is fetched for your account's SEB perimeter. If the list comes
> back empty, your account may live in a different perimeter — pass
> `dcp_context` to `list_devices()` / `RowxplorerClient.seb()` (e.g.
> `dcp_context="ROWENTA_FR"`).

## Installation

```bash
pip install rowxplorer-lib
```

## Getting started

### 1. Get your `refresh_token` (one-off)

Sign in with your SEB/Rowenta account. The library runs the full OAuth flow
and prints the long-lived `refresh_token`:

```bash
rowxplorer-lib login --user you@example.com --password SECRET
```

Store the printed `refresh_token` — it is the only long-lived secret you need.
(You can also do this in code, see below.)

### 2. Discover your robot

Set the `refresh_token` and list the robots paired with your account. The
`uuid` is the `ROBOT_ID` you need:

```bash
export IOT_REFRESH_TOKEN=<your refresh_token>
rowxplorer-lib --seb devices
# [
#   {
#     "name": "My Robot",
#     "uuid": "01234567-89ab-cdef-0123-456789abcdef",
#     "thing_type": "VAC001",
#     "appliance": "APPLIANCE_1234",
#     "source": "IOTHUB"
#   }
# ]
```

### 3. Configure the robot

Set the remaining environment variables (or pass them in code):

```bash
export IOT_MQTT_ENDPOINT=prod-new.iot.mqtt.groupe-seb.com
export ROBOT_ID=<uuid from the previous step>
```

### 4. Control the robot

```bash
rowxplorer-lib --seb status
rowxplorer-lib --seb clean-all
rowxplorer-lib --seb go-home
rowxplorer-lib --seb stop
```

## Usage

### As a library

**Log in** (one-off, to obtain the `refresh_token`):

```python
from rowxplorer_lib import SebAuth, SebAuthConfig

auth = SebAuth(SebAuthConfig(user="you@example.com", password="SECRET"))
tokens = auth.login()
print(tokens.refresh_token)  # store this
```

**Control the robot** (using the stored `refresh_token`):

```python
from rowxplorer_lib import RowxplorerClient, SebAuthConfig, SebMqttConfig

client = RowxplorerClient.seb(
    auth_config=SebAuthConfig(refresh_token="TU_REFRESH_TOKEN"),
    mqtt_config=SebMqttConfig(
        mqtt_endpoint="prod-new.iot.mqtt.groupe-seb.com",
        robot_id="TU_ROBOT_ID",  # the robot UUID (appliance asset id)
    ),
)

print(client.status())  # RobotStatus
client.clean_all()      # clean the whole house
client.stop()           # pause
client.go_home()        # back to the dock
```

**List the robots** in the account:

```python
from rowxplorer_lib import RowxplorerClient

client = RowxplorerClient.seb(auth_config=SebAuthConfig(refresh_token="TU_REFRESH_TOKEN"))
for dev in client.list_devices():
    print(dev.name, dev.uuid, dev.thing_type)
```

`RowxplorerClient.seb()` with no arguments reads the `IOT_*` variables from
the environment (the library never reads a `.env` file — export them yourself).

### Multi-robot

Accounts can have several robots. Target one of them by UUID (`robot_id`) or
by name/UUID (`device`, resolved via `list_devices()` — this also sets the
matching `product_id`):

```python
from rowxplorer_lib import RowxplorerClient

# by name (or UUID) — picks the robot and its thing type
client = RowxplorerClient.seb(device="My Robot")

# or by UUID directly
client = RowxplorerClient.seb(robot_id="01234567-89ab-cdef-0123-456789abcdef")

print(client.status())
```

From the CLI, use `--device`:

```bash
rowxplorer-lib --seb --device "My Robot" status
```

### CLI

```bash
# one-off: get your refresh_token
rowxplorer-lib login --user you@example.com --password SECRET

# list the robots in the account (the uuid is the ROBOT_ID)
rowxplorer-lib --seb devices

# control the robot (reads IOT_* env vars)
rowxplorer-lib --seb status
rowxplorer-lib --seb clean-all
rowxplorer-lib --seb go-home
rowxplorer-lib --seb stop
rowxplorer-lib --seb localize           # beep
rowxplorer-lib --seb set-power STRONG   # suction power
rowxplorer-lib --seb set-method SPIRAL  # cleaning method

# multi-robot: target a specific robot by name or UUID
rowxplorer-lib --seb --device "My Robot" status
```

## Device compatibility

| Device                          | Product ID | Status      |
| ------------------------------- | ---------- | ----------- |
| Rowenta X-Plorer 45             | `VAC001`   | ✅ Verified |
| Other Groupe SEB robots (same SEB cloud platform) | — | ⚠️ Not verified |

Compatibility with models other than the X-Plorer 45 is not guaranteed; it
depends on the robot using the same SEB cloud platform and topic layout.

## Commands

| Method                | CLI          | Action                          |
| --------------------- | ------------ | ------------------------------- |
| `list_devices()`      | `devices`    | list the robots in the account  |
| `status()`            | `status`     | current status (battery, …)     |
| `clean_all()`         | `clean-all`  | clean the whole house           |
| `clean_spot()`        | `clean-spot` | spot clean                      |
| `stop()`              | `stop`       | pause                           |
| `abort()`             | `abort`      | abort                           |
| `go_home()`           | `go-home`    | back to the dock                |
| `explore()`           | `explore`    | explore / map (not on SEB)      |
| `continue_cleaning()` | `continue`   | resume                          |
| `localize()`          | `localize`   | beep                            |
| `set_power(p)`        | `set-power`  | suction power (e.g. `STRONG`)   |
| `set_method(m)`       | `set-method` | cleaning method (e.g. `SPIRAL`) |

> `explore()` is part of the client API but is not implemented on the SEB
> cloud path (the only enabled transport); calling it raises
> `NotImplementedError`.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check src tests
```

## License

MIT — see [LICENSE](LICENSE).
