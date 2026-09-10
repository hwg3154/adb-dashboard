# Remote key press, text and touch emulation with adb

How to press hardware/virtual buttons, type text and drive the UI of a device from a remote
workstation (USB or Wi-Fi) with the device-side `input` tool.

- Upstream command reference: `adb shell input --help` (the `input` tool lives on the device,
  so options depend on the Android release installed there)
- Key code names: [KeyEvent — Key codes](https://developer.android.com/reference/android/view/KeyEvent#key_codes)
- adb itself: `docs/adb-command-reference.md`

## 1. Command shape

```bash
adb [-d | -e | -s <serial>] shell input [args] <source> <command> [args]
```

`input` is not an `adb` subcommand: everything after `shell` is executed on the device. Because of
that, quoting follows the normal adb rules (see `docs/adb-command-reference.md`, "Quoting").

Sources (`args` before the command, when a build supports them): `keyboard`, `keyboard_l`, `touch`,
`touchpad`, `joystick`, `trackball`, `mouse`, `stylus`, `dpad`, `gesture`, `voice`.
Always assume the smallest common set (`text`, `keyevent`, `tap`, `swipe`) and use `--help` when a
specific build must be verified:

```bash
adb shell input --help
adb -s emulator-5554 shell input keyevent --help
```

## 2. Supported commands

| Command | Syntax | Notes |
|---|---|---|
| `text` | `input text <string>` | Type into the focused input field |
| `keyevent` | `input keyevent [options] <keycode>` | One key press; keycode may be a `KEYCODE_*` name or its number |
| `tap` | `input tap <x> <y>` | Single tap in display coordinates (0,0 = top-left) |
| `swipe` | `input swipe <x1> <y1> <x2> <y2> [duration_ms]` | Drag from one point to another |
| `draganddrop` | `input draganddrop <x1> <y1> <x2> <y2> [duration_ms]` | Press, move, release; also selects text |
| `roll` | `input roll <dx> <dy>` | Trackball / joystick movement |
| `rolltouchpad` | `input rolltouchpad <dx> <dy>` | Touchpad scroll gesture |
| `mouse` | `input mouse <click\|dblclick\|move\|up\|down\|moveanddown\|moveandup> [x] [y]` | Mouse pointer events |
| `keycombination` | `input keycombination <down\|up\|downup> <keycode> [<keycode> ...]` | Modifier + key; support varies per release |
| `keyevent --longpress` | `input keyevent --longpress <keycode>` | Hold the key instead of a short press |
| `keyevent --press` | `input keyevent --press <key_down> <key_up>` | Custom key-down / key-up mapping (e.g. a key with different behavior per state) |
| `keyevent --repeat` | `input keyevent --repeat <count> <keycode>` | Auto-repeat, useful for volume or d-pad navigation |
| `keyevent --interval` | `input keyevent --interval <ms> <keycode>` | Wait between generated key events |

Coordinate values are pixels of the *current* orientation. Query them first when the layout is unknown:

```bash
adb shell wm size
adb shell wm density
adb shell uiautomator dump /sdcard/window_dump.xml && adb pull /sdcard/window_dump.xml
```

## 3. Key codes

Prefer the `KEYCODE_*` name: it is stable across devices, and `adb` resolves it to the number for
you. The number works too but is opaque and easy to transpose.

| Key code | Effect |
|---|---|
| `KEYCODE_HOME` | Go to the home screen |
| `KEYCODE_BACK` | Back / close the current screen |
| `KEYCODE_APP_SWITCH` | Open the recent apps (overview) screen |
| `KEYCODE_MENU` | Open the options menu |
| `KEYCODE_MY_APP_LIST` | Open the app list (TV) |
| `KEYCODE_TAB` | Tab forward |
| `KEYCODE_SPACE` | Space |
| `KEYCODE_ENTER` | Enter / IME action |
| `KEYCODE_DEL` | Delete (backspace) |
| `KEYCODE_FORWARD_DEL` | Forward delete |
| `KEYCODE_INSERT` | Insert |
| `KEYCODE_ESCAPE` | Escape |
| `KEYCODE_MOVE_HOME` / `KEYCODE_MOVE_END` | Cursor to start / end of text |
| `KEYCODE_PAGE_UP` / `KEYCODE_PAGE_DOWN` | Scroll a page up / down |
| `KEYCODE_DPAD_CENTER` | Select the focused item (also used for on-screen clicks on TV) |
| `KEYCODE_DPAD_UP` / `_DOWN` / `_LEFT` / `_RIGHT` | Navigate with the d-pad |
| `KEYCODE_VOLUME_UP` / `KEYCODE_VOLUME_DOWN` | Volume rocker up / down |
| `KEYCODE_VOLUME_MUTE` | Toggle mute |
| `KEYCODE_MUTE` | Mute the ringer |
| `KEYCODE_POWER` | Toggle the screen; long press opens the power menu |
| `KEYCODE_SLEEP` / `KEYCODE_WAKEUP` | Force sleep / wake without ending calls |
| `KEYCODE_CAMERA` | Launch the camera / take a photo |
| `KEYCODE_FOCUS` | Focus the camera (half-press) |
| `KEYCODE_SEARCH` | Invoke search |
| `KEYCODE_ASSIST` | Invoke the assistant |
| `KEYCODE_VOICE_ASSIST` | Voice input |
| `KEYCODE_MEDIA_PLAY` / `KEYCODE_MEDIA_PAUSE` / `KEYCODE_MEDIA_PLAY_PAUSE` | Playback control |
| `KEYCODE_MEDIA_STOP` / `_NEXT` / `_PREVIOUS` | Transport controls |
| `KEYCODE_MEDIA_REWIND` / `KEYCODE_MEDIA_FAST_FORWARD` | Seek backward / forward |
| `KEYCODE_MEDIA_RECORD` | Start recording |
| `KEYCODE_MEDIA_SKIP_FORWARD` / `KEYCODE_MEDIA_SKIP_BACKWARD` | Skip tracks (when supported) |
| `KEYCODE_MEDIA_AUDIO_TRACK` / `KEYCODE_MEDIA_THUMBS_UP` / `KEYCODE_MEDIA_THUMBS_DOWN` / `KEYCODE_MEDIA_CLOSE` | Media app specific actions |
| `KEYCODE_CHANNEL_UP` / `KEYCODE_CHANNEL_DOWN` | Channel up / down |
| `KEYCODE_GUIDE` / `KEYCODE_INFO` / `KEYCODE_CAPTIONS` / `KEYCODE_SETTINGS` | TV guide, info, subtitles, settings |
| `KEYCODE_TV_*` (e.g. `KEYCODE_TV_PROGRAM_GUIDE`, `KEYCODE_TV_INPUT`, `KEYCODE_TV_MODE_SETTING`, `KEYCODE(tv_...)`) | TV-only keys; availability varies |
| `KEYCODE_STB_*` | Set-top-box style keys |
| `KEYCODE_BRIGHTNESS_UP` / `KEYCODE_BRIGHTNESS_DOWN` | Brightness rocker |
| `KEYCODE_NAVIGATE_IN` / `_OUT` / `_NEXT` / `_PREVIOUS` | D-pad alternatives for focus navigation |
| `KEYCODE_PAIRING` / `KEYCODE_PAIRING...` | Pairing-related keys on some devices |
| `KEYCODE_SYSRQ`, `KEYCODE_BREAK`, `KEYCODE_NUM_LOCK`, `KEYCODE_CAPS_LOCK`, `KEYCODE_SCROLL_LOCK` | Keyboard state keys |
| `KEYCODE_BUTTON_*` (`KEYCODE_BUTTON_A/B/C/X/Y/Z`, `KEYCODE_BUTTON_L1/L2/R1/R2`, `KEYCODE_BUTTON_START`, `KEYCODE_BUTTON_SELECT`, `KEYCODE_BUTTON_MODE`, `KEYCODE_BUTTON_THUMBL/R`) | Gamepad buttons |
| `KEYCODE_0` … `KEYCODE_9`, `KEYCODE_A` … `KEYCODE_Z` | Alphanumeric keys |
| `KEYCODE_SOFT_LEFT` / `KEYCODE_SOFT_RIGHT` | Soft keys |
| `KEYCODE_SETTINGS`, `KEYCODE_BOOKMARK`, `KEYCODE_TASK_MANAGER`, `KEYCODE_POWER`, `KEYCODE_CAMERA`, `KEYCODE_VOLUME_*`, `KEYCODE_MUSIC`, `KEYCODE_PLAY`, `KEYCODE_PAUSE`, `KEYCODE_RECORD`, `KEYCODE_PLAYBACK`, `KEYCODE_ZOOM_IN`, `KEYCODE_ZOOM_OUT` | Additional media/system keys with device specific meaning |
| `KEYCODE_UNKNOWN` | Unknown or unmapped key |

Notes for key presses:
- A key code is delivered as a key-down followed by a key-up. Apps that only react to a real press
  (long-press gestures, drag handles, keyboard layouts) may ignore synthetic events.
- Injected events carry a "not from a real user" flag. Android 10+ delivers them to the focused
  window, and apps may legitimately drop them: permission dialogs, lock screens, payment/2FA
  screens, `filterTouchesWhenObserved` views and apps that require a real user gesture.
- Injected key events do **not** grant more privileges than a real tap; the `shell` user does not
  need `INJECT_EVENTS` because the platform grants it to adb, but do not use key injection to
  bypass app or OS consent screens.

## 4. Worked examples

```bash
# 1) Discover the device first: everything below needs exactly one target
adb devices -l

# 2) Home, back, recents
adb shell input keyevent KEYCODE_HOME
adb shell input keyevent KEYCODE_BACK
adb shell input keyevent KEYCODE_APP_SWITCH

# 3) Type text into the focused field
adb shell input text 'hello'
adb shell input text 'hello%sthello'          # %s = space
adb shell input text "path\sto/file"          # escape what the shell would eat
adb shell "input text \"quoted\""             # double quoting

# 4) Tap and swipe (pixels)
adb shell input tap 540 960
adb shell input swipe 300 1200 300 300 400     # scroll up, 400 ms
adb shell input draganddrop 200 400 700 900 600

# 5) Navigate a TV-style UI with the d-pad
adb shell input keyevent KEYCODE_DPAD_DOWN
adb shell input keyevent KEYCODE_DPAD_CENTER

# 6) Long press (power menu)
adb shell input keyevent --longpress KEYCODE_POWER

# 7) Volume up three times, with a delay between presses
for i in 1 2 3; do adb shell input keyevent KEYCODE_VOLUME_UP; sleep 0.3; done

# 8) Media playback
adb shell input keyevent KEYCODE_MEDIA_PLAY
adb shell input keyevent KEYCODE_MEDIA_PAUSE
adb shell input keyevent KEYCODE_MEDIA_NEXT

# 9) Device selected explicitly (multiple devices attached)
adb -s 192.168.1.23:5555 shell input keyevent KEYCODE_VOLUME_DOWN

# 10) Screenshot + text in one flow, binary-safe
adb exec-out screencap -p > screen.png
```

## 5. Replacing a hardware remote control (TV / set-top boxes)

Recommended flow: connect once, then map remote buttons to `input keyevent`.

1. Pair and connect once: `adb pair 192.168.1.23:37000`, then `adb connect 192.168.1.23:5555`.
2. Keep a single long-lived connection; reconnect with `adb reconnect` and `adb devices`.
3. Map each remote button to a `KEYCODE_*` name; use `keyevent` only (never `tap`) for keys that
   the UI can also receive from a real remote, because a tap depends on the current layout.
4. Keep a short delay between events (≈150–300 ms). Consecutive `adb` calls in a tight loop drop
   events on slow devices and confuse animations.
5. For media keys (`KEYCODE_MEDIA_*`) verify the target app is in the foreground; media keys are
   routed to the media session owner.
6. `--longpress` gives a real hold (power menu, context menus, camera half-press).
7. Do not try to emulate the power key on a device that a user is actively using: it locks the
   screen for everybody and cannot be undone by adb.

## 6. Diagnostics and verification

| Goal | Command |
|---|---|
| Which window receives the events | `adb shell dumpsys window displays \| grep -i focus` (or `mFocusedApp`) |
| Input dispatch problems | `adb shell dumpsys input` |
| Live key event trace | `adb shell getevent -lt` (Ctrl+C to stop) |
| Supported key codes / options | `adb shell input --help` |
| Keyboard visibility | `adb shell settings get secure show_ime_with_hard_keyboard` |
| Show the soft keyboard even with a hardware keyboard | `adb shell settings put secure show_ime_with_hard_keyboard 1` |
| Switch the active IME | `adb shell ime list -s` / `adb shell ime set <ime-id>` |
| Screen size for coordinates | `adb shell wm size`, `adb shell wm density` |

Common failures:

| Message | Cause and fix |
|---|---|
| `adb: more than one device/emulator` | Add `-s <serial>`, `-d` or `-e` |
| `adb: device offline` / `unauthorized` | Accept the RSA dialog, `adb kill-server`, re-plug |
| `adb: device 'X' not found` | Serial is wrong or the device went away; re-run `adb devices -l` |
| Command prints nothing and does nothing | The focused window consumes nothing: unlock the device, tap into the field, or the view filters injected events |
| `SecurityException: Injecting to another application requires INJECT_EVENTS permission` | A non-adb process tried to inject; only the adb/shell user may inject key and touch events |
| Spaces, `&`, `;`, `(`, `)`, `$` break `input text` | Quote twice (see `docs/adb-command-reference.md`) and use `%s` for spaces |

## 7. Etiquette and safety

- Injecting keys and text is full remote control of the device. Use it only on devices you own or
  are authorized to administer, with the user's knowledge.
- Never automate away security prompts, permission grants, payment confirmations or 2FA codes.
- Key injection is a debugging/automation aid, not an accessibility replacement: a real remote or an
  accessibility service is the correct tool for end users.
- `adb` traffic over USB is unencrypted at the application layer; Wi-Fi adb relies on TLS plus the
  pairing code. Keep `$ADB_VENDOR_KEYS` private and don't ship an adb key in an app package.
