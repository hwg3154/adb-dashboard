# Android TV Web Dashboard — design doc (v1)

Product: `tvdashboard`, a single lightweight Docker container that exposes a browser dashboard for
controlling **one** Android TV over wireless ADB.

Related:
- `docs/adb-command-reference.md` — adb syntax, global options, discovery/connection commands
- `docs/remote-key-press.md` — `input keyevent` / `input text` semantics and etiquette

This file is the product and security contract for the code in `tvdashboard/`. adb syntax questions
are answered in the two docs above; this file does not duplicate them.

## 1. Scope

v1 is deliberately small: a remote, not a device manager.

In scope:
- Keyboard-driven navigation: d-pad, Back, Home, Menu, Captions, Sleep, and Wake over the network.
- Text entry into the focused field on the TV, with a "Send to TV" field and an explicit Enter key.
- App launcher: list launchable apps, launch, force-stop, app info, clear data, uninstall.
- Quick launch: one tile per streaming service from a fixed catalogue, each switched on or off
  by the operator in Settings.
- Media, volume and TV tiles; on-demand screenshot.
- First-run setup wizard with network discovery, and password auth for a single operator.
- Device registry (nickname, model, `host:port`), manual "Forget device".
- One layout that works on a phone and on a desktop: the pad, the essential keys and quick
  launch first, everything else in one flat grid.

Out of scope for v1: logcat, file browser, live screen mirroring, multi-user accounts,
per-app settings editor, "Drive TV" hard toggle, env-seeded admin, TLS termination.

## 2. Locked decisions

| Area | Decision |
|---|---|
| UI style | Server-rendered HTML + ~15 KB vanilla JS. No SPA, no framework, no build step. |
| Keyboard | Focus-based capture: keys are forwarded only while the remote panel has focus; `Esc` is Back and `Shift`+`Esc` releases; a visible "Remote: active" indicator and a Release button are always present. |
| Layout | One responsive page, not a separate mobile site. Mobile-first CSS, 44px+ touch targets, no hover-only affordance. |
| Screen | No screen view at all. Screenshot button only, no stream, no mjpeg. |
| Auth | First-run wizard, single operator account, no public registration, no password recovery. |
| Transport | Plain HTTP, LAN-only. Security lives in the application layer, not in TLS. |
| Discovery | Native `asyncio` TCP sweep + UDP broadcast. No `nmap`. |
| Dependencies | Runtime deps: none from PyPI required. `argon2-cffi` optional, `hashlib.scrypt` fallback. |
| Forbidden | `nmap`, `ffmpeg`, `aiohttp`, `requests`, any file-watching loop. |

## 3. Architecture

```
browser (static/ + inline tokens)
   │  fetch() JSON, form POSTs
   ▼
tvdashboard.web        HTTP server (stdlib ThreadingHTTPServer), routing, JSON I/O
   ├── tvdashboard.views    server-rendered pages, HTML escaping, template files
   ├── tvdashboard.api      JSON endpoints: key/text/launch/stop/screenshot/discover/devices
   ├── tvdashboard.adb      argv builder + subprocess runner (shell=False, timeout, bounded output)
   ├── tvdashboard.registry device registry + TTL cache, atomic JSON state in /data
   ├── tvdashboard.auth     password hash, sessions, rate limit
   ├── tvdashboard.security origin/host checks, CSRF, cookie flags, SSRF guard
   ├── tvdashboard.discovery asyncio sweep + UDP broadcast
   └── tvdashboard.wol      Wake-on-LAN magic packet, ARP lookup, adb-port awake check
```

`python -m tvdashboard` starts the server. No daemon, no background threads other than the
accept loop; state is read from disk on demand and cached with a TTL.

## 4. Keyboard model

- The remote panel is a focusable region (`tabindex="0"`, autofocused on load).
- Only while that region has focus does the client forward keys. Typing into dashboard `input`
  elements never reaches the TV.
- `Esc` is **Back**. It is the key a remote uses to go back, and pretending otherwise made the
  most-pressed key on the keyboard do nothing to the TV.
- Releasing the keyboard is `Shift`+`Esc`, the "Release keyboard" button next to the indicator,
  or clicking outside the panel. The button is always rendered once the script runs — hiding it
  while idle made it vanish under the pointer between `mousedown` and `click`.
- Client sends one JSON request per key press; server maps the name through an allowlist and
  builds argv itself.
- Keys are rate limited per session so a stuck key or a scripted flood cannot hammer the device.

| Client key | Forwarded keycode |
|---|---|
| ArrowUp / Down / Left / Right | `KEYCODE_DPAD_UP` / `_DOWN` / `_LEFT` / `_RIGHT` |
| Esc | `KEYCODE_BACK` (`Shift`+`Esc` is not forwarded: it releases the panel) |
| Enter | `KEYCODE_DPAD_CENTER` (OK) |
| Back / Home / Menu | `KEYCODE_BACK` / `KEYCODE_HOME` / `KEYCODE_MENU` |
| Captions | `KEYCODE_CAPTIONS` |
| Sleep | `KEYCODE_SLEEP` |
| Media play / pause / rewind / fast-forward | `KEYCODE_MEDIA_*` |
| Volume up / down / mute | `KEYCODE_VOLUME_UP` / `KEYCODE_VOLUME_DOWN` / `KEYCODE_VOLUME_MUTE` |

`KEYCODE_SLEEP` is confirm-gated: it switches the TV off for everybody in the room.

**Wake is not a key.** A sleeping TV has no adb to receive one, so Wake is a Wake-on-LAN magic
packet sent to the most recently used TV (§7). There is no Power key: it toggles, so it could
switch off a TV you meant to turn on.

## 5. Text entry

Single line field, `Send to TV`. Server-side:
- length cap (512 chars), reject empty, reject control characters,
- space → `%s`, quote for the device shell, single argv element,
- no IME control: the TV keyboard owns IME selection, autocomplete and non-Latin scripts.

## 6. Launcher

Enumerate only apps that resolve a `LEANBACK_LAUNCHER` or `LAUNCHER` activity, in that order of
preference. Per app the UI offers: Launch, Force stop, App info, Clear data, Uninstall.
The destructive ones are behind a confirm. v1 shows package names, not friendly labels: label
lookup costs a `dumpsys package` per app and is not worth it.

## 6.1 Quick launch

The launcher answers "what is on this TV". Quick launch answers "put Netflix on", which is the
thing people actually do, so it is the first panel on the page.

- `platforms.py` is a fixed catalogue: alias → label → candidate packages. The browser sends
  `netflix`; it never sends, and never receives, a package name. An alias outside the catalogue
  is refused before any device lookup, exactly like an unknown key.
- A service ships under more than one package (an Android TV build, a phone build, a regional
  variant), so each entry lists candidates most-likely-first. A launch tries the next candidate
  only when the device says the previous one is not there, capped at three attempts. When an
  app list has been fetched this session, a candidate known to be installed is tried first.
- Every catalogued package must satisfy the same pattern `adb.py` enforces. A real package that
  cannot (`air.ITVMobilePlayer`) is left out rather than special-cased.
- Which tiles are shown is an operator preference, stored server-side in `prefs.json` so the
  phone and the laptop agree. The file holds aliases and nothing else: a hand-edited file cannot
  introduce a package name. Settings always lists the whole catalogue, on and off, or a tile
  switched off could never be switched back on.
- Each checkbox is its own small form carrying one alias, so the no-JS path works and one POST
  carries one decision.

## 7. Setup and device registry

First run (no account yet): wizard → network discovery → candidate list → optional pairing code →
persist → repeat.

Candidate verification is **not** a full adb handshake. The server opens a bare TCP socket to the
candidate, then reads `ro.product.*` properties over an adb connection. A candidate that yields no
properties is reported as "not a TV" and is not persisted.

- Candidates are stored server-side in a short-lived TTL cache; the browser sends an opaque
  `candidate_id`, never a host or port.
- **Typing an address is a first-class path.** Discovery cannot see a TV on another subnet, a
  TV that was asleep during the sweep, or anything at all from a NATted container, so
  `/api/devices/add` accepts an address from the browser. This is the one place a host comes
  from outside, and it is held to exactly the guard in §9: dotted IPv4, RFC1918 only, and a
  configured adb port. It cannot be aimed at loopback, link-local or off the LAN.
- **Pairing uses its own address.** Android 11+ shows a pairing address with a fresh random
  port next to the six-digit code, and lists the connect address separately. They are asked
  for separately because they are different: pairing against the connect port always fails.
  The pairing port is therefore allowed to be any ephemeral port, while the host rule is
  unchanged.
- **A connection is not state we can persist.** It lives in the adb server, so it is gone
  after a restart, a reboot, or a long enough sleep - while the pairing and the registry entry
  are still perfectly good. Every device command therefore reconnects once if adb says the
  device is not there, and retries. Only a connection failure is retried: a command the device
  received and refused is never sent twice.
- **Waking a sleeping TV.** In standby the TV closes every port, so nothing over adb can reach
  it. It needs networked standby (on TCL: energy mode *Optimised – networked standby*), which
  keeps its network card listening for a Wake-on-LAN magic packet. The packet needs the TV's
  MAC, and this machine can only learn that while the TV is awake: it is read from this
  machine's own ARP table after a successful command and kept in the registry. The browser
  never supplies a MAC or an address - Wake always targets the most recently used TV.
- **Quick launch wakes first.** A press checks whether the TV's adb port answers. If it does,
  the app launches as before. If not, it sends Wake-on-LAN, pauses 3 s, keeps checking for up
  to 10 s more until the port answers, then launches. The check is a TCP connect to the adb
  port, not ICMP: a TV in networked standby can answer ping while adb is down, and ping needs a
  privilege the container drops. With no MAC learned yet it simply launches as before.
- The registry is keyed by `host:port` with nickname, model and timestamps; only "Forget device"
  deletes an entry.
- All state lives in `TVD_DATA_DIR` (default `/data`), directory `0700`, files `0600`,
  written temp-file + `os.replace`. There is no file watching. The files are `accounts.json`,
  `sessions.json`, `devices.json` and `prefs.json`; a read-only data directory costs the
  quick-launch choice at restart and nothing else.

## 8. Interfaces

Browser (HTML): `/`, `/apps`, `/settings`, `/setup`, `/login`, `/static/...`. One page, one
layout: there is no separate mobile site to keep in step.

JSON API (all `POST`, all JSON, fixed shape, size-capped):

| Endpoint | Body | Result |
|---|---|---|
| `/api/key` | `{"key": "..."}` | keycode sent, elapsed ms |
| `/api/text` | `{"text": "...", "submit": bool}` | text injected |
| `/api/launch` | `{"package": "..."}` | launch intent sent |
| `/api/quick_launch` | `{"platform": "netflix"}` | catalogued app started |
| `/api/prefs/quick_launch` | `{"alias": "netflix", "on": "0"}` | tile shown or hidden |
| `/api/stop` | `{"package": "..."}` | force-stop sent |
| `/api/appinfo` | `{"package": "..."}` | system App Info opened |
| `/api/clear` | `{"package": "..."}` | app data cleared |
| `/api/uninstall` | `{"package": "..."}` | package removed |
| `/api/apps` | `{}` | launchable app list |
| `/api/screenshot` | `{}` | PNG as base64, truncated if oversized |
| `/api/discover` | `{}` | candidate list (id/host/port/score) |
| `/api/join` | `{"candidate_id": "...", "pairing_code": "..."}` | device joined |
| `/api/devices/add` | `{"host": "...", "port": "..."}` | device added by typed address |
| `/api/pair` | `{"pair_address": "...", "pairing_code": "...", "host": "..."}` | paired, then connected |
| `/api/wake` | `{}` | Wake-on-LAN sent to the last TV used |
| `/api/devices/{id}/connect` | `{}` | connected |
| `/api/devices/{id}/disconnect` | `{}` | disconnected |
| `/api/devices/{id}/forget` | `{}` | forgotten |

`/login` accepts one query parameter, `?e=<code>`, and it is the only one on the site. A failed
`/api/login` form POST answers `303 /login?e=bad_credentials` so the browser lands on a form it
can retype into, instead of on a page of JSON with no way back — that was the v0 dead end. The
code is validated against a fixed table (`views.LOGIN_NOTICES`) which owns the wording, so the
browser can choose which sentence appears but can never supply one. A `fetch()` caller still gets
`401 {"error": "bad_credentials"}`; only the form path redirects.

Rules for every endpoint:
- Arguments come from an internal allowlist plus validated values. **Never** string interpolation:
  argv is a `list[str]`, `shell=False`, per-call timeout, bounded output.
- `GET` is for HTML only; anything that can change device or app state is `POST`.
- Error responses are stable codes (`bad_key`, `unauthorized`, `no_device`, `adb_missing`, …) and
  never echo user input or device strings back into HTML without escaping.
- A form POST that fails lands back on the page it came from with `?e=<code>`; the page turns
  the code into a sentence from a table it owns (`views.LOGIN_NOTICES`, `views.SETUP_NOTICES`),
  so no handler and no crafted link can put words on a page. A `fetch()` caller still gets JSON.

## 8.1 Interfaces intentionally absent

- `logcat`: unbounded, high-entropy output and an excellent way to leak device content into a
  browser log panel.
- file browser / `pull` / `push`: a filesystem bridge on a LAN appliance is a much wider attack
  surface than "control one TV".
- live mirroring: needs `ffmpeg` or WebRTC, and turns the appliance into a video server.
- `input tap` / `swipe`: layout-dependent; keys from a fixed map are the reliable remote.

## 9. Security requirements

- Argon2id password hashing (`argon2-cffi` when present), falling back to `hashlib.scrypt`.
  Per-user random salt; generic error on bad credentials; no user enumeration, including in timing
  (an unknown username is verified against a decoy hash generated in the same scheme).
- Server-side sessions: 256-bit random token, stored **hashed**; cookie `HttpOnly` + `SameSite=Lax`,
  path-scoped; idle + absolute expiry; logout revokes. `Secure` only when TLS is terminated in front.
- Origin validated against the request's own `Host` (a wildcard listener answers on every LAN
  address, so a single configured origin cannot be the reference); `Sec-Fetch-Site` refuses
  `cross-site`; an opaque `Origin: null` is refused. CSRF token on every form
  and every JSON body, `X-Content-Type-Options: nosniff`, no unescaped device strings in HTML.
- Login rate limiting: per-IP and per-username budget with backoff, plus a global cap.
- SSRF hygiene: targets must be IPv4 **RFC1918 only**; reject loopback, link-local, multicast,
  `0.0.0.0`, `169.254.169.254`; no hostnames; ports fixed to `5555`–`5557`; discovery capped to
  one `/24`.
- Wake-on-LAN is the only other broadcast the server sends: a fixed 102-byte magic packet to UDP
  port 9, built from a validated MAC, sent only to the last-used TV's own address and the
  broadcast addresses of its `/24`. Nothing in it, and nothing about where it goes, comes from
  the browser.
- Device discovery never returns a candidate before the RFC1918/loopback guard has been applied.
- Logs: structured JSON, one line per request; credentials and tokens redacted; user-entered text
  is never logged, only its length.
- Image: `python:3.12-slim`, multi-arch (arm64 + amd64) with Debian `adb`, non-root user, read-only
  rootfs, `no-new-privileges`, dropped capabilities, default seccomp, no `--privileged`.
- `$HOME/.android` must be writable **and persistent**: adb keeps its RSA key there, and a new
  key makes the TV demand the wireless-debugging dialog again, which only someone at the TV can
  accept. A read-only rootfs without that volume breaks `adb connect` outright.
- No cloud, no telemetry, no CDN assets. All assets are served from the container.

## 10. Known limitations

These are product decisions, not bugs; do not "fix" them by weakening the checks above.

- **Android 11+ refuses unpaired `adb connect`.** The wizard must run `adb pair` first, against
  the *pairing* port the TV displays - not the connect port - and the code is regenerated every
  time the dialog is opened. Someone has to be at the TV to read it. There is no remote way to
  do this.
- **`input text` is weak at IME.** No IME selection, poor non-Latin support; the TV keyboard
  handles those itself. Injected text does not survive fields that reject synthesized input.
- **Injected keys are dropped** by permission, payment, 2FA and `filterTouchesWhenObserved`
  screens. We do not attempt to evade that, and we do not offer a way to retry around it.
- **Wake needs networked standby, and the dashboard on the TV's network.** Without networked
  standby the TV's network card is off and hears nothing. The packet is a broadcast, so the
  dashboard must share the TV's segment: bridged networking for a VM, host networking for
  Docker. A unicast copy is also aimed at the TV's own address, which may get through from a
  NATted host, but that is not something to rely on.
- **Docker Desktop on macOS NATs the container**, so LAN broadcast discovery is unreliable there.
  Unicast sweep and manual entry are the fallback. On Linux hosts prefer `--network=host` so
  mDNS/broadcast works.
- One operator at a time. Two browsers fighting over the keyboard is an unsolved, accepted
  trade-off of the single-account design.

## 11. Configuration

| Variable | Default | Meaning |
|---|---|---|
| `TVD_DATA_DIR` | `/data` | state directory (registry, accounts, sessions) |
| `TVD_HTTP_ADDR` | `0.0.0.0:8080` | listen address |
| `TVD_ALLOW_INSECURE_HTTP` | unset | `1` = serve plain HTTP without a warning page |
| `TVD_ALLOWED_CIDRS` | RFC1918 | comma-separated discovery/connect scope |
| `TVD_MDNS` | unset | `1` = add best-effort mDNS to discovery |
| `TVD_ADB_BIN` | `adb` | adb binary path |

## 12. Testing

- **Unit**: keycode map, text sanitizer (spaces, quotes, `$`, `&`, `;`, control chars), argv builder
  (no interpolation), RFC1918/loopback guard, candidate dedupe, the quick-launch catalogue
  (every package passes adb's own pattern), the preference file (aliases only, survives a
  reload), and the `?e=` notice table.
- **Contract**: a fake `adb` executable on `PATH` returning canned `list targets` / `discover` /
  `pm list packages` / `pm list package` output; asserts argv shape and that no string is
  interpolated.
- **Integration**: one manual checklist for the wizard (discover → verify → pair → connect → launch
  → screenshot). Real TV behaviour is not covered by CI and stays manual.
- **HTTP**: the sign-in retry (wrong password → `303` → a page with the form on it, JSON callers
  unchanged), quick launch by alias, and the preference round-trip through the running server.
- Not in CI: the browser-level checks that `Esc` reaches the TV as Back, that `Shift`+`Esc` sends
  nothing, and that every page still works with JavaScript switched off. Those need a browser;
  they stay in the manual checklist.
- Run: `python3 -m unittest discover -s tests`.

## 13. Related

- `docs/adb-command-reference.md` — adb syntax and command tables
- `docs/remote-key-press.md` — key injection, text entry, etiquette
