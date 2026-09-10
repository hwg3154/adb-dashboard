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
- Keyboard-driven navigation: d-pad, Enter, Back, Home, Menu, Channel ±, Guide, Info, Captions,
  Aspect-Ratio, Power/Sleep/Wake.
- Text entry into the focused field on the TV, with a "Send to TV" field and an explicit Enter key.
- App launcher: list launchable apps, launch, force-stop, app info, clear data, uninstall.
- Media, volume and TV tiles; on-demand screenshot.
- First-run setup wizard with network discovery, and password auth for a single operator.
- Device registry (nickname, model, `host:port`), manual "Forget device".

Out of scope for v1: logcat, file browser, live screen mirroring, multi-user accounts,
per-app settings editor, "Drive TV" hard toggle, env-seeded admin, TLS termination.

## 2. Locked decisions

| Area | Decision |
|---|---|
| UI style | Server-rendered HTML + ~15 KB vanilla JS. No SPA, no framework, no build step. |
| Keyboard | Focus-based capture: keys are forwarded only while the remote panel has focus; Esc releases; a visible "Remote: active" indicator is always present. |
| Screen | No screen view at all. Screenshot button only, no stream, no mjpeg. |
| Auth | First-run wizard, single operator account, no public registration, no password recovery. |
| Transport | Plain HTTP, LAN-only. Security lives in the application layer, not in TLS. |
| Discovery | Native `asyncio` TCP sweep + UDP broadcast. No `nmap`. |
| Dependencies | Runtime deps: none from PyPI required. `argon2-cffi`/`bcrypt` optional, `hashlib.scrypt` fallback. |
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
   └── tvdashboard.discovery asyncio sweep + UDP broadcast
```

`python -m tvdashboard` starts the server. No daemon, no background threads other than the
accept loop; state is read from disk on demand and cached with a TTL.

## 4. Keyboard model

- The remote panel is a focusable region (`tabindex="0"`, autofocused on load).
- Only while that region has focus does the client forward keys. Typing into dashboard `input`
  elements never reaches the TV.
- `Esc` releases the panel (indicator turns off) and stops forwarding until the panel is clicked
  or focused again.
- Client sends one JSON request per key press; server maps the name through an allowlist and
  builds argv itself.
- Keys are rate limited per session so a stuck key or a scripted flood cannot hammer the device.

| Client key | Forwarded keycode |
|---|---|
| ArrowUp / Down / Left / Right | `KEYCODE_DPAD_UP` / `_DOWN` / `_LEFT` / `_RIGHT` |
| Enter (in text context) | `KEYCODE_ENTER` |
| Back / Home / Menu | `KEYCODE_BACK` / `KEYCODE_HOME` / `KEYCODE_MENU` |
| Channel up / down | `KEYCODE_CHANNEL_UP` / `KEYCODE_CHANNEL_DOWN` |
| Guide / Info / Captions / Aspect | `KEYCODE_GUIDE` / `KEYCODE_INFO` / `KEYCODE_CAPTIONS` / `KEYCODE_TV_ASPECT_RATIO` |
| Power / Sleep / Wake | `KEYCODE_POWER` / `KEYCODE_SLEEP` / `KEYCODE_WAKEUP` |
| Media play / pause / next / prev / seek | `KEYCODE_MEDIA_*` |
| Volume up / down / mute | `KEYCODE_VOLUME_UP` / `KEYCODE_VOLUME_DOWN` / `KEYCODE_VOLUME_MUTE` |
| Mic | `KEYCODE_VOICE_ASSIST` |

`KEYCODE_POWER` is a confirm-gated action (it locks the screen for everybody in the room).

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

## 7. Setup and device registry

First run (no account yet): wizard → network discovery → candidate list → optional pairing code →
persist → repeat.

Candidate verification is **not** a full adb handshake. The server opens a bare TCP socket to the
candidate, then reads `ro.product.*` properties over an adb connection. A candidate that yields no
properties is reported as "not a TV" and is not persisted.

- Candidates are stored server-side in a short-lived TTL cache; the browser only ever sends an
  opaque `candidate_id`, never a host or port.
- The registry is keyed by `host:port` with nickname, model and timestamps; only "Forget device"
  deletes an entry.
- All state lives in `TVD_DATA_DIR` (default `/data`), directory `0700`, files `0600`,
  written temp-file + `os.replace`. There is no file watching.

## 8. Interfaces

Browser (HTML): `/`, `/apps`, `/settings`, `/setup`, `/login`, `/static/...`.

JSON API (all `POST`, all JSON, fixed shape, size-capped):

| Endpoint | Body | Result |
|---|---|---|
| `/api/key` | `{"key": "..."}` | keycode sent, elapsed ms |
| `/api/text` | `{"text": "...", "submit": bool}` | text injected |
| `/api/launch` | `{"package": "..."}` | launch intent sent |
| `/api/stop` | `{"package": "..."}` | force-stop sent |
| `/api/appinfo` | `{"package": "..."}` | system App Info opened |
| `/api/clear` | `{"package": "..."}` | app data cleared |
| `/api/uninstall` | `{"package": "..."}` | package removed |
| `/api/apps` | `{}` | launchable app list |
| `/api/screenshot` | `{}` | PNG as base64, truncated if oversized |
| `/api/discover` | `{}` | candidate list (id/host/port/score) |
| `/api/join` | `{"candidate_id": "...", "pairing_code": "..."}` | device joined |
| `/api/devices/{id}/connect` | `{}` | connected |
| `/api/devices/{id}/disconnect` | `{}` | disconnected |
| `/api/devices/{id}/forget` | `{}` | forgotten |

Rules for every endpoint:
- Arguments come from an internal allowlist plus validated values. **Never** string interpolation:
  argv is a `list[str]`, `shell=False`, per-call timeout, bounded output.
- `GET` is for HTML only; anything that can change device or app state is `POST`.
- Error responses are stable codes (`bad_key`, `unauthorized`, `no_device`, `adb_missing`, …) and
  never echo user input or device strings back into HTML without escaping.

## 8.1 Interfaces intentionally absent

- `logcat`: unbounded, high-entropy output and an excellent way to leak device content into a
  browser log panel.
- file browser / `pull` / `push`: a filesystem bridge on a LAN appliance is a much wider attack
  surface than "control one TV".
- live mirroring: needs `ffmpeg` or WebRTC, and turns the appliance into a video server.
- `input tap` / `swipe`: layout-dependent; keys from a fixed map are the reliable remote.

## 9. Security requirements

- Argon2id password hashing (`argon2-cffi` when present), `bcrypt` fallback, then `hashlib.scrypt`.
  Per-user random salt; generic error on bad credentials; no user enumeration, including in timing.
- Server-side sessions: 256-bit random token, stored **hashed**; cookie `HttpOnly` + `SameSite=Lax`,
  path-scoped; idle + absolute expiry; logout revokes. `Secure` only when TLS is terminated in front.
- Origin / `Sec-Fetch-Site` + `Host` validation on state-changing requests, CSRF token on every form
  and every JSON body, `X-Content-Type-Options: nosniff`, no unescaped device strings in HTML.
- Login rate limiting: per-IP and per-username budget with backoff, plus a global cap.
- SSRF hygiene: targets must be IPv4 **RFC1918 only**; reject loopback, link-local, multicast,
  `0.0.0.0`, `169.254.169.254`; no hostnames; ports fixed to `5555`–`5557`; discovery capped to
  one `/24`.
- Device discovery never returns a candidate before the RFC1918/loopback guard has been applied.
- Logs: structured JSON, one line per request; credentials and tokens redacted; user-entered text
  is never logged, only its length.
- Image: `python:3.12-slim`, multi-arch (arm64 + amd64) with Debian `adb`, non-root user, read-only
  rootfs, `no-new-privileges`, dropped capabilities, default seccomp, no `--privileged`.
- No cloud, no telemetry, no CDN assets. All assets are served from the container.

## 10. Known limitations

These are product decisions, not bugs; do not "fix" them by weakening the checks above.

- **Android 11+ refuses unpaired `adb connect`.** The wizard must run `adb pair` first, and the
  TV's *Allow USB debugging* / wireless-debugging dialog must be accepted by someone physically at
  the TV. There is no remote way to do this.
- **`input text` is weak at IME.** No IME selection, poor non-Latin support; the TV keyboard
  handles those itself. Injected text does not survive fields that reject synthesized input.
- **Injected keys are dropped** by permission, payment, 2FA and `filterTouchesWhenObserved`
  screens. We do not attempt to evade that, and we do not offer a way to retry around it.
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
  (no interpolation), RFC1918/loopback guard, candidate dedupe.
- **Contract**: a fake `adb` executable on `PATH` returning canned `list targets` / `discover` /
  `pm list packages` / `pm list package` output; asserts argv shape and that no string is
  interpolated.
- **Integration**: one manual checklist for the wizard (discover → verify → pair → connect → launch
  → screenshot). Real TV behaviour is not covered by CI and stays manual.
- Run: `python3 -m unittest discover -s tests`.

## 13. Related

- `docs/adb-command-reference.md` — adb syntax and command tables
- `docs/remote-key-press.md` — key injection, text entry, etiquette
