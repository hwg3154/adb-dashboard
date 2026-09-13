# tvdashboard

A browser dashboard for controlling **one** Android TV over wireless adb, packaged as a single
container. Server-rendered HTML, one small vanilla-JS file, no framework, no build step, and no
runtime dependency that is not in the standard library.

The product and security contract is [docs/design.md](docs/design.md). adb syntax lives in
[docs/adb-command-reference.md](docs/adb-command-reference.md) and
[docs/remote-key-press.md](docs/remote-key-press.md).

## What it does

- A remote: a d-pad with Back, Home, Menu and Play in the corners, then volume and search, then
  one row with media, captions, **Sleep** and **Wake**. Keys are forwarded only while the remote
  panel has focus; `Esc` sends **Back**, and `Shift`+`Esc` (or the Release button) hands the
  keyboard back to the page.
- Wake over the network: **Wake** sends Wake-on-LAN to the last TV you used, and a quick-launch
  tile wakes a sleeping TV before launching, so one press gets you into the app. The TV needs
  networked standby on (TCL: energy mode *Optimised – networked standby*), and the dashboard
  must be on the TV's network - bridged, if it runs in a VM. It learns the TV's MAC by itself
  the first time you use any button while the TV is on.
- Quick launch: one tile per streaming service — Netflix, Disney+, Prime Video, YouTube and
  HBO Max are on by default, and Settings has a checkbox for every app in the catalogue so the
  ones you do not have never appear. A service with artwork shows its logo; the rest show their
  name.

  To add a logo, drop a `png`, `jpg` or `webp` into `tvdashboard/static/logos/` named for the
  catalogue alias in `tvdashboard/platforms.py` (`netflix.jpg`, `prime_video.png`, …). It is
  picked up at start-up. A file named after anything else is ignored, and no SVGs: the server
  will not serve a format that can carry script. The full-size originals live in `logos/`.
- A "Send to TV" text field for the focused input on the device.
- A launcher: list launchable apps, launch, force stop, app info, clear data, uninstall.
- One screenshot, on request. There is no stream and no screen view.
- A first-run wizard that sweeps the LAN, pairs and connects - or you can just type the TV's
  IP address, which is the reliable path when the scan cannot see it (different subnet, TV
  asleep, or a NATted container).
- Connections look after themselves: adb forgets a device whenever it restarts, so every
  command reconnects once and retries rather than making you re-pair.
- The same page on a phone: the pad, the essential keys and quick launch come first and are
  sized for a thumb; the rest collapses. There is no separate mobile site.

## Run it

With Docker (see [docker-compose.yml](docker-compose.yml)):

```bash
docker compose up --build
```

Then open `http://<host>:8080` and create the operator password. A wrong password comes back to
the sign-in form with an error, so you can just try again. There is no password reset: if it is
lost, clear the data volume and start again.

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
| `TVD_DATA_DIR` | `/data` | state directory (accounts, sessions, device registry, preferences) |
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

- `test_units.py` — keycode map, text sanitizer, RFC1918/loopback guard, candidate dedupe, the
  quick-launch catalogue and the preference file.
- `test_contract.py` — a fake `adb` on disk that records argv, asserting the exact command shape
  and that no browser string is ever interpolated into one.
- `test_http.py` — the real server on a loopback port: first run, sign-in and the retry after a
  wrong password, CSRF, cookies, the origin checks, rate limiting, quick launch, and the device
  paths against the fake adb.

Real TV behaviour is not covered and stays a manual checklist (design.md §12), as does anything
that needs a browser: `Esc` reaching the TV as Back, `Shift`+`Esc` releasing, and the pages
working with JavaScript switched off.

## Security posture in one paragraph

Plain HTTP on a trusted LAN; the defences are in the application. One operator account with
Argon2id (scrypt fallback) hashing and a rate-limited login; server-side sessions stored hashed,
`HttpOnly` + `SameSite=Lax`; CSRF token on every state-changing request; `Origin` checked against
the request's own `Host` and `Sec-Fetch-Site` refused when `cross-site`. Every adb call is built
from a fixed argv template with `shell=False`, a timeout and bounded output — the browser names a
key alias or a package, never a command. Targets must be RFC1918 IPv4 on an adb port, so the
dashboard cannot be aimed at anything but a TV on your own network.
