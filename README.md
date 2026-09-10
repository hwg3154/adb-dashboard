# tvdashboard

A browser dashboard for controlling **one** Android TV over wireless adb, packaged as a single
container. Server-rendered HTML, one small vanilla-JS file, no framework, no build step, and no
runtime dependency that is not in the standard library.

The product and security contract is [docs/design.md](docs/design.md). adb syntax lives in
[docs/adb-command-reference.md](docs/adb-command-reference.md) and
[docs/remote-key-press.md](docs/remote-key-press.md).

## What it does

- A remote: d-pad, Back/Home/Menu, channel, guide/info/captions, media, volume, power.
  Keys are forwarded only while the remote panel has focus; `Esc` releases it.
- A "Send to TV" text field for the focused input on the device.
- A launcher: list launchable apps, launch, force stop, app info, clear data, uninstall.
- One screenshot, on request. There is no stream and no screen view.
- A first-run wizard that sweeps the LAN, pairs and connects.

## Run it

With Docker (see [docker-compose.yml](docker-compose.yml)):

```bash
docker compose up --build
```

Then open `http://<host>:8080` and create the operator password. There is no password reset:
if it is lost, clear the data volume and start again.

Without Docker:

```bash
TVD_DATA_DIR=./var TVD_HTTP_ADDR=127.0.0.1:8080 TVD_ALLOW_INSECURE_HTTP=1 python3 -m tvdashboard
```

`adb` must be on `PATH` (or set `TVD_ADB_BIN`). The server starts without it and says so, but
every device command will fail.

### Two things that will bite you in a container

- **Networking.** On Linux use `network_mode: host` so the sweep and the UDP probe reach the TV.
  Docker Desktop on macOS and Windows NATs the container, so discovery is unreliable there and
  you are down to the unicast sweep.
- **The adb key.** adb writes its RSA key to `$HOME/.android/adbkey`. That path must be writable
  *and* persistent, or every restart generates a new key and the TV demands the wireless-debugging
  dialog again — which only someone standing at the TV can accept. The compose file mounts a
  volume for it; a read-only rootfs without that volume breaks `adb connect` outright.

## Configuration

Environment only; there are no command-line options.

| Variable | Default | Meaning |
|---|---|---|
| `TVD_DATA_DIR` | `/data` | state directory (accounts, sessions, device registry) |
| `TVD_HTTP_ADDR` | `0.0.0.0:8080` | listen address |
| `TVD_ALLOW_INSECURE_HTTP` | unset | `1` = plain HTTP without the warning banner, and no `Secure` cookie |
| `TVD_ALLOWED_CIDRS` | RFC1918 | comma-separated discovery/connect scope |
| `TVD_DEVICE_PORTS` | `5555,5556,5557` | adb ports to sweep |
| `TVD_ADB_BIN` | `adb` | adb binary |

Full table, including the tuning knobs, in [docs/design.md](docs/design.md) §11.

## Tests

```bash
python3 -m unittest discover -s tests
```

Three layers, no network and no device required:

- `test_units.py` — keycode map, text sanitizer, RFC1918/loopback guard, candidate dedupe.
- `test_contract.py` — a fake `adb` on disk that records argv, asserting the exact command shape
  and that no browser string is ever interpolated into one.
- `test_http.py` — the real server on a loopback port: first run, sign-in, CSRF, cookies, the
  origin checks, rate limiting, and the device paths against the fake adb.

Real TV behaviour is not covered and stays a manual checklist (design.md §12).

## Security posture in one paragraph

Plain HTTP on a trusted LAN; the defences are in the application. One operator account with
Argon2id (scrypt fallback) hashing and a rate-limited login; server-side sessions stored hashed,
`HttpOnly` + `SameSite=Lax`; CSRF token on every state-changing request; `Origin` checked against
the request's own `Host` and `Sec-Fetch-Site` refused when `cross-site`. Every adb call is built
from a fixed argv template with `shell=False`, a timeout and bounded output — the browser names a
key alias or a package, never a command. Targets must be RFC1918 IPv4 on an adb port, so the
dashboard cannot be aimed at anything but a TV on your own network.
