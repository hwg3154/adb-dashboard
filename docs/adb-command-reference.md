# adb command reference

Primary source: [Android Debug Bridge (adb) — Issuing commands](https://developer.android.com/tools/adb#issuingcommands)
Local snapshot: `docs/adb-site-reference.md` (fetched 2026-09-08)

`adb` is the client–server command line tool used to control an Android device or emulator:

- **client** – the `adb` binary you run on the workstation, sends commands
- **daemon (adbd)** – runs on each device, executes the commands
- **server** – background process on the workstation, multiplexes clients to devices (TCP port **5037**)

```bash
adb [-d | -e | -s <serial>] <command>
```

Install: adb ships with the SDK **Platform-Tools** package (`$ANDROID_HOME/platform-tools/adb`).
Sanity check: `adb version`, `adb help`.

## Global options

| Option | Description |
|---|---|
| `-a` | Listen on all network interfaces, not only localhost |
| `-d` | Use the (single) USB device; errors out when several devices are attached |
| `-e` | Use the (single) TCP/IP (emulator) device; errors out when several are available |
| `-s SERIAL` | Target the device with this serial number; overrides `$ANDROID_SERIAL` |
| `-t ID` | Target the device with this transport id |
| `-H HOST` | adb server host (default `localhost`) |
| `-P PORT` | adb server port (default `5037`) |
| `-L SOCKET` | Socket the server listens on (default `tcp:localhost:5037`) |
| `--one-device SERIAL|USB` | Only for `start-server` / `server nodaemon`: restrict the server to one USB device |
| `--exit-on-write-error` | Exit as soon as stdout is closed |

## Targeting a device (item specification)

Useful device selectors:

| Spec | Description |
|---|---|
| `-s SERIAL` | Select a device by serial (`-s emulator-5554`, `-s 0.0.0.0:6520`, `-s 192.168.1.5:5555`) |
| `-d` | Select the only USB device (fails with more than one) |
| `-e` | Select the only emulator (fails with more than one) |
| `-t ID` | Select by transport id |
| `$ANDROID_SERIAL` | Default serial when `-s` is missing; `-s` wins |

## Discovering and connecting

| Command | Description |
|---|---|
| `adb devices [-l]` | List attached devices. `-l` adds product/model/device info. Per line: `SERIAL state [description]` |
| `adb connect HOST[:PORT]` | Connect to a device over TCP/IP (default port `5555`) |
| `adb disconnect [HOST[:PORT]]` | Disconnect one device, or all of them |
| `adb pair HOST[:PORT] [PAIRING-CODE]` | Pair for secure TCP/IP communication (Android 11+ pairing dialog / QR code) |
| `adb usb` | Restart adbd listening on USB |
| `adb tcpip PORT` | Restart adbd listening on TCP `PORT` |
| `adb mdns check` | Report whether mDNS discovery is available |
| `adb mdns services` | List discovered mDNS services (`_adb-tls-connect._tcp`, …) |
| `adb wait-for[-TRANSPORT]-STATE` | Block until a device reaches `STATE` (`device`, `recovery`, `rescue`, `sideload`, `bootloader`, `disconnect`); `TRANSPORT` is `usb`, `local` or `any` (default `any`) |
| `adb get-state` | Print `offline`, `unauthorized`, `bootloader`, `sidedeload`, `connecting` or `device` |
| `adb get-serialno` | Print the device serial number |
| `adb get-devpath` | Print the device path |
| `adb help` / `adb --help` | Print the built-in command list |
| `adb version` | Print adb version |
| `adb start-server` / `adb kill-server` | Start / stop the adb server |
| `adb reconnect [device|offline]` | Force reconnect from host side, device side, or for offline/unauthorized devices |
| `adb attach` / `adb detach` | Attach a detached USB device / detach it for other processes |

Device states: `offline` (not connected or not responding), `device` (connected and usable — reached before boot completes), `no device` (nothing attached).

### adb over Wi-Fi, short version

1. Enable **Developer options → USB debugging** (hidden before Android 4.2, unlock it in Settings).
2. Accept the *Allow USB debugging* RSA dialog on the device.
3. `adb devices` → the serial is listed as `device`.
4. For wireless: `adb pair ipaddr:port` + pairing code, then `adb connect ipaddr:port`.
   Keep host and device on the same network; unpair via *Wireless debugging → Paired devices → Forget*
   or *Revoke adb debugging authorizations*.

## Installing and managing apps

| Command | Description |
|---|---|
| `adb install [-lrtsdg] [--instant] APK` | Push one APK and install it |
| `adb install-multiple [-lrtsdpg] [--instant] APK...` | Push several APKs of one package (splits) and install them together |
| `adb install-multi-package [-lrtsdpg] PACKAGE...` | Push one or more packages and install them atomically |
| `adb uninstall [-k] PACKAGE` | Remove the package; `-k` keeps data and cache |

`install` flags: `-r` replace existing, `-t` allow test packages, `-d` allow version downgrade (debuggable only), `-s` install to SD card (legacy), `-g` grant all runtime permissions, `--abi ABI` override platform ABI, `--instant` install as ephemeral app, `--streaming` / `--no-streaming` stream the APK directly, `--fastdeploy` / `--no-fastdeploy` / `--force-agent` / `--date-check-agent` / `--version-check-agent` / `--local-agent` tune the fast-deploy agent.

```bash
adb install -r -t app-debug.apk
adb install-multiple base.apk lib_arm64.apk
adb uninstall -k com.example.app
```

## Copying files

| Command | Description |
|---|---|
| `adb push [-n] [-q] [-Z] [-z ALGORITHM] [--sync] LOCAL... REMOTE` | Copy files/dirs to the device |
| `adb pull [-a] [-q] [-Z] [-z ALGORITHM] REMOTE... LOCAL` | Copy files/dirs from the device |
| `adb sync [-l] [-n] [-q] [-Z] [-z ALGORITHM] [all|data|odm|oem|product|system|system_ext|vendor]` | Push a local build from `$ANDROID_PRODUCT_OUT` (default `all`) |

Flags: `-n` dry run (do not write), `-q` quiet (no progress), `-Z` disable compression, `-z ALGORITHM` pick a compressor (`any`/`none`/`brotli`/`lz4`/`zstd`), `-a` preserve mtime and mode, `-l` list files that would be copied, `--sync` copy only files whose timestamps differ.

```bash
adb push myfile.txt /sdcard/myfile.txt
adb pull /sdcard/screen.png .
adb shell ls -l /sdcard
```

## Shell access

| Command | Description |
|---|---|
| `adb [-d|-e|-s SERIAL] shell [COMMAND...]` | Run a command on the device; with no `COMMAND` start an interactive shell |
| `adb exec-out COMMAND...` | Like `shell`, but stdout is streamed back to the client as raw bytes |
| `adb emu COMMAND` | Send a command to the emulator console |

`shell` flags: `-e ESCAPE` choose the escape char (default `~`, `none` disables it), `-n` do not read stdin, `-T` do not allocate a pty, `-t` allocate a pty when stdin is a tty (`-tt` forces it), `-x` disable remote exit codes and stdout/stderr separation.

**Quoting (Platform-Tools 23+).** `adb shell` passes arguments like `ssh(1)`: the local shell eats the first level of quoting, so quote values twice and avoid bare metacharacters.

```bash
adb shell setprop key "'two words'"     # correct
adb shell setprop key 'two words'       # wrong: device sees `setprop key two words`
adb shell "am start -a android.intent.action.VIEW -d 'tel:5551234'"
adb exec-out screencap -p > screen.png  # binary-safe, no CRLF translation
```

Android ships most usual Unix tools (`toybox`): `adb shell ls /system/bin`, `adb shell toybox --help`.

## Device-side commands reachable through adb

Each of these is a device command, not an `adb` subcommand. Run it as `adb shell <command>`, and use `--help` (or `help`) to list its own options.

| Command | Description |
|---|---|
| `am` | Activity manager: start activities/services, broadcast intents, force-stop, kill, profile, dump heap, display props |
| `pm` | Package manager: list/query/install/uninstall/clear, grant/revoke permissions, enable/disable, installer, app links, device quarantine, abort/commit staged sessions |
| `dpm` | Device policy manager: set active admin / profile owner / device owner, freeze-period record, force network & security logs |
| `input` | Inject key presses, text and touch events (**see `docs/remote-key-press.md`**) |
| `svc` | Toggle device services: `usb`, `wifi`, `bt`, `data`, `voiceroam`, `verbose data saver` |
| `settings` | Read/write system / secure / global settings |
| `wm` | Window manager: density, size, folding features, overview, folding-enable |
| `uiautomator` | `dump` the view hierarchy, `runtest` UiAutomator tests |
| `appops` | Inspect and change app operation (appop) restrictions |
| `monkey` | Pseudo-random UI stress testing and intent/component launch |
| `monkey` variants: `monkey -v -s SEED ...` | see `monkey --help` |
| `content` | Query/insert/update/delete provider data, watch for changes |
| `location` | Manage and fake mock locations |
| `telephony` | Telephony commands such as network selection |
| `ime` | List and switch input methods (IMEs) |
| `screencap` | Capture the display to a PNG file |
| `screenreade` (see below) | — |
| `screenrecord` | Record the display to an MP4 file |
| `bmgr` | Backup manager: set backup transport, backup/restore state |
| `appwidget` | Bind and unbind app widgets |
| `sqlite3` | Operate on databases on the device |
| `profile`, `profile start|stop`, `profile status`, `profile reset` | ART profile collection |
| `bugreport` | Write a bug report |

Notes:
- `am` options: `-D` debug, `-W` wait for launch, `--start-profiler`, `-P`, `-R count`, `-S` force-stop first, `--opengl-trace`, `--user`, `--debug-link` (Android 17+).
- `pm` install flags: `-l -r -i -s -f -t -a -d -g --fast-dependency --non-required ...` (see `pm --help`).
- `screencap` filename can be omitted: the PNG goes to stdout.
- `screenrecord` stops on `Control+C` or after 3 minutes / `--time-limit`.
- Audio is **not** recorded by `screenrecord`, and recording is unavailable on Wear OS.
- Older `appops --user` / `appops --uid` semantics changed: the uid option applies to device
  stored state only and does not override the app's current user (Android 12).
- `pm` device-quarantine and `app-link` options require the `WRITE_DEVICE_STORED_QUARANTINE`
  or `CHANGE_DEVICE_INTENTION` permission and are only available to system apps.
- The `adb` shell user can only access its own `/data` locations and cannot gain extra
  privileges on user builds.

## Local state and device reset

| Command | Description |
|---|---|
| `adb reboot [bootloader|recovery|sideload|sideload-auto-reboot|fastboot]` | Reboot the device |
| `adb remount [-R]` | Remount partitions read-write; `-R` reboots when required |
| `adb disable-verity` / `adb enable-verity` | Turn dm-verity off / on (userdebug builds) |
| `adb root` / `adb unroot` | Restart adbd with / without root |
| `adb sideload OTAPACKAGE` | Sideload a full OTA package |
| `adb keygen FILE` | Generate the adb RSA key pair (private key in `FILE`) |

## Diagnostics

| Command | Description |
|---|---|
| `adb logcat [options]` | Show the device log (`adb shell logcat --help`) |
| `adb bugreport [PATH]` | Write a bug report to `PATH` (default `bugreport.zip`); unsupported devices write to stdout |
| `adb jdwp` | List pids of processes hosting a JDWP transport |

## Port forwarding

```bash
adb forward [--no-rebind] LOCAL REMOTE   # host -> device
adb reverse [--no-rebind] REMOTE LOCAL   # device -> host
adb forward --list
adb reverse --list
adb forward --remove LOCAL
adb reverse --remove REMOTE
adb forward --remove-all
adb reverse --remove-all
```

`LOCAL` accepts `tcp:PORT` (or `tcp:0` for any free port), `localabstract:NAME`, `localreserved:NAME`, `localfilesystem:PATH`, `dev:NAME`, `dev-raw:NAME`, `jdwp:PID` (remote only), `vsock:CID:PORT` (remote only), `acceptfd:FD` (listen only).
`REMOTE` for `reverse` accepts `tcp:PORT` (or `tcp:0`), `localabstract:NAME`, `localreserved:NAME`, `localfilesystem:PATH`.

```bash
adb forward tcp:6100 tcp:7100
adb forward tcp:6100 local:logd
```

## Environment variables

| Variable | Description |
|---|---|
| `$ADB_TRACE` | Comma/space separated debug categories: `all,adb,sockets,packets,rwx,usb,sync,sysdeps,transport,jdwp,services,auth,fdevent,shell,incremental` |
| `$ADB_VENDOR_KEYS` | Colon-separated list of key files or directories |
| `$ANDROID_SERIAL` | Default target serial (overridden by `-s`) |
| `$ANDROID_LOG_TAGS` | Default `logcat` tag filters |
| `$ADB_LOCAL_TRANSPORT_MAX_PORT` | Highest emulator port scanned (default `5585`, 16 emulators) |
| `$ADB_MDNS_AUTO_CONNECT` | Comma-separated mDNS services allowed to auto-connect (default `_adb-tls-connect._tcp`) |

## Behavior notes worth knowing

- **adb 37.0.0 / Android 17** introduce *adb Burst Mode*: one `adb` command can drive several
  connected devices at once and aggregate their output. `adb --help` and `adb server-status` are
  the way to check the running feature set.
- adb locates emulators by scanning odd ports **5555–5585** (console on the even port below, e.g.
  console `5554` ↔ adb `5555`). A start order race can hide an emulator from `adb devices`
  (`adb kill-server && adb start-server` fixes it), or keep the default port choice.
- `adb` never prints `List of devices attached` for an emulator that is still in `offline`.
- `adb shell` without a command is interactive: exit with `Control+D` or `exit`.
- Binary output must go through `adb exec-out`, not `adb shell` (the latter translates `\n` → `\r\n`).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `adb: more than one device/emulator` | Add `-s SERIAL`, `-d` or `-e` |
| `adb: device unauthorized` | Accept the RSA dialog on the device; `adb kill-server` then retry; check `$ADB_VENDOR_KEYS` |
| Device listed as `offline` | `adb kill-server`, `adb start-server`, re-plug USB |
| Emulator missing from `adb devices` | `adb kill-server` then `adb start-server`; let the emulator pick its own port; keep ≤16 emulators |
| `adb: device not found` | Re-check serial with `adb devices -l`; do not reuse another device's serial |
| `adb connect` refused / no auth dialog | Enable *Always allow from this computer*, verify the firewall and that host+device share the network; check `adb server-status` for `mdns_enabled: true` and `mdns_backend: LIBADBMDNS` |

## Related

- `docs/remote-key-press.md` — remote key press, text entry and touch emulation
- `docs/adb-site-reference.md` — vendored copy of the official adb guide used to build this file
