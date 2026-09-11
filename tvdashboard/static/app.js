/* Android TV Dashboard - client.
 *
 * Four jobs, and nothing else:
 *   1. forward keys to the TV, but only while the remote panel has focus (design.md §4)
 *   2. turn the plain <form> POSTs into fetch() calls so a key press does not reload the page
 *   3. confirm the destructive actions, and fetch a screenshot on request
 *   4. flip a quick-launch checkbox without a page reload
 *
 * Every page still works with this file blocked: the forms POST normally and the server
 * redirects back. Nothing here decides what is allowed - the server re-checks every request.
 */
(function () {
  "use strict";

  var CSRF = (document.querySelector('meta[name="tvd-csrf"]') || {}).content || "";
  var HEADER = "X-TVD-CSRF";
  var state = document.getElementById("remote-state");
  var panel = document.getElementById("remote-panel");
  var release = document.getElementById("remote-release");

  /* The browser key names we forward, mapped to the server's aliases. Anything not in this
     map is left to the page, so Tab, F5 and the browser's own shortcuts still work.

     Escape is Back, because that is what the key means on a remote. Letting go of the
     keyboard is Shift+Esc, handled before this map is consulted. */
  var KEYS = {
    ArrowUp: "dpad_up",
    ArrowDown: "dpad_down",
    ArrowLeft: "dpad_left",
    ArrowRight: "dpad_right",
    Enter: "dpad_center",
    Escape: "back",
    Esc: "back",
    " ": "play_pause",
    Backspace: "back",
    Home: "home",
    ContextMenu: "menu",
    PageUp: "channel_up",
    PageDown: "channel_down",
    MediaPlayPause: "play_pause",
    MediaTrackNext: "media_next",
    MediaTrackPrevious: "media_previous",
    MediaStop: "media_stop",
    AudioVolumeUp: "volume_up",
    AudioVolumeDown: "volume_down",
    AudioVolumeMute: "volume_mute"
  };

  /* Forms that move the browser themselves (cookies, redirects). Left to post normally. */
  var NATIVE_FORMS = { "/api/login": true, "/api/change_password": true, "/api/logout": true };

  var active = false;
  var busy = false;

  function say(message, isError) {
    if (!state) return;
    state.textContent = message;
    state.classList.toggle("on", !!active && !isError);
    state.classList.toggle("error", !!isError);
  }

  function setActive(on) {
    active = !!on;
    /* The button is always there once this file runs - only its label changes. Hiding it on
       blur would make it vanish under the pointer between mousedown and click, which is a
       button that can never be pressed. */
    if (release) release.textContent = active ? "Release keyboard" : "Use keyboard";
    say(active ? "Remote: active" : "Remote: idle", false);
  }

  /* ------------------------------------------------------------------ transport */

  function post(url, body) {
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", [HEADER]: CSRF },
      body: JSON.stringify(Object.assign({ csrf: CSRF }, body || {}))
    })
      .then(function (response) {
        return response
          .json()
          .catch(function () {
            return { ok: false, error: "bad_response" };
          })
          .then(function (payload) {
            payload.status = response.status;
            return payload;
          });
      })
      .catch(function () {
        return { ok: false, error: "offline", status: 0 };
      });
  }

  /* A failure the operator can act on, in the one status line we have. */
  function report(payload, done) {
    if (payload.ok) {
      say(done || (active ? "Remote: active" : "Remote: idle"), false);
      return true;
    }
    if (payload.error === "unauthorized") {
      window.location.href = "/login";
      return false;
    }
    say(MESSAGES[payload.error] || "Failed: " + (payload.error || "unknown"), true);
    return false;
  }

  var MESSAGES = {
    no_device: "No TV is paired yet - open Set up TV.",
    adb_missing: "adb is not installed in this container.",
    adb_failed: "The TV did not accept that.",
    rate_limited: "Too many keys at once - slowing down.",
    bad_key: "That key is not on the remote.",
    bad_text: "Nothing safe to send in that text.",
    bad_package: "That app name is not valid.",
    bad_platform: "That app is not in the quick-launch list.",
    connect_failed: "Could not connect to the TV.",
    pairing_failed: "The TV rejected that pairing code.",
    offline: "The dashboard is unreachable."
  };

  function sendKey(alias) {
    if (busy) return;
    busy = true;
    post("/api/key", { key: alias }).then(function (payload) {
      busy = false;
      report(payload);
    });
  }

  /* ------------------------------------------------------------------ keyboard */

  if (panel) {
    panel.addEventListener("focus", function () {
      setActive(true);
    });
    panel.addEventListener("blur", function () {
      setActive(false);
    });
    panel.addEventListener("click", function () {
      panel.focus();
    });
    /* Arm the keyboard on load without letting the browser scroll the panel into view -
       that used to jump the page past the quick-launch row every time it opened. */
    try {
      panel.focus({ preventScroll: true });
    } catch (err) {
      panel.focus();
    }
    setActive(document.activeElement === panel);
  }

  if (release) {
    /* Without this the button steals focus from the panel on mousedown, so by the time the
       click arrives the remote is already idle and the toggle reads the wrong state. */
    release.addEventListener("mousedown", function (event) {
      event.preventDefault();
    });
    release.addEventListener("click", function (event) {
      event.stopPropagation();
      if (!panel) return;
      if (active) {
        panel.blur();
        setActive(false);
      } else {
        panel.focus();
      }
    });
    release.hidden = false;
  }

  document.addEventListener("keydown", function (event) {
    if (!active) return;

    /* Typing into a field of our own is typing, not remote control. */
    var tag = (event.target && event.target.tagName) || "";
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;

    /* Shift+Esc is the way out: it hands the keyboard back to the page and is never
       forwarded. Esc on its own is Back, which is what a remote does with it. */
    if ((event.key === "Escape" || event.key === "Esc") && event.shiftKey) {
      if (panel) panel.blur();
      setActive(false);
      event.preventDefault();
      return;
    }

    if (event.ctrlKey || event.metaKey || event.altKey) return;
    if (event.shiftKey && event.key.length === 1) return;

    var alias = KEYS[event.key];
    if (!alias) return;
    event.preventDefault();
    sendKey(alias);
  });

  /* ------------------------------------------------------------------ forms */

  /* Every POST form becomes a fetch(), so a key press or an app action does not reload the
     page. A form we do not recognise is left alone and submits normally. */
  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!form || form.method.toLowerCase() !== "post") return;
    var action = form.getAttribute("action") || "";
    if (action.indexOf("/api/") !== 0) return;
    if (NATIVE_FORMS[action]) return;

    var confirmText = form.getAttribute("data-confirm");
    if (confirmText && !window.confirm(confirmText)) {
      event.preventDefault();
      return;
    }

    event.preventDefault();
    var body = {};
    var data = new FormData(form);
    data.forEach(function (value, name) {
      if (name !== "csrf") body[name] = value;
    });
    /* The submit button's own name/value is not in FormData for a programmatic submit. */
    var submitter = event.submitter;
    if (submitter && submitter.name) body[submitter.name] = submitter.value;

    post(action, body).then(function (payload) {
      if (!report(payload, doneMessage(action, body))) return;
      if (action === "/api/prefs/quick_launch") {
        flipChoice(form);
        return;
      }
      if (RELOAD_AFTER[action]) window.location.reload();
    });
  });

  function doneMessage(action, body) {
    if (action === "/api/quick_launch") return "Launched " + (body.platform || "app");
    if (action === "/api/prefs/quick_launch") return "Saved";
    return "Done";
  }

  /* Actions that change what the page is showing. */
  var RELOAD_AFTER = {
    "/api/join": true,
    "/api/discover": true,
    "/api/uninstall": true,
    "/api/devices/use": true,
    "/api/devices/remove": true,
    "/api/devices/set_nickname": true
  };

  /* A quick-launch checkbox: the server stored the new state, so flip the row to match
     rather than reloading a settings page the operator is halfway through. */
  function flipChoice(form) {
    var field = form.querySelector('input[name="on"]');
    var button = form.querySelector("button.check");
    var box = form.querySelector(".box");
    if (!field) return;
    var nowOn = field.value === "1";
    field.value = nowOn ? "0" : "1";
    form.classList.toggle("on", nowOn);
    if (box) box.innerHTML = nowOn ? "&#10003;" : "";
    if (button) button.setAttribute("aria-checked", nowOn ? "true" : "false");
  }

  /* A tile carrying data-confirm is a destructive key (Power, Sleep). */
  document.addEventListener("click", function (event) {
    var tile = event.target.closest && event.target.closest(".tile[data-confirm]");
    if (!tile) return;
    if (!window.confirm(tile.getAttribute("data-confirm"))) event.preventDefault();
  });

  /* ------------------------------------------------------------------ screenshot */

  var shot = document.querySelector("img.screen");
  if (shot) {
    var button = document.createElement("button");
    button.type = "button";
    button.textContent = "Take screenshot";
    button.className = "shot";
    shot.parentNode.insertBefore(button, shot);
    button.addEventListener("click", function () {
      button.disabled = true;
      say("Screenshot...", false);
      post("/api/screenshot", {}).then(function (payload) {
        button.disabled = false;
        if (!report(payload, "Screenshot taken")) return;
        shot.src = "data:image/png;base64," + payload.png;
        shot.alt = "TV screenshot";
      });
    });
  }

  /* ------------------------------------------------------------------ setup */

  var candidates = document.querySelector("ul.candidates");
  if (candidates) {
    var scan = document.createElement("button");
    scan.type = "button";
    scan.textContent = "Scan the network";
    candidates.parentNode.insertBefore(scan, candidates);
    scan.addEventListener("click", function () {
      scan.disabled = true;
      say("Scanning...", false);
      post("/api/discover", {}).then(function (payload) {
        scan.disabled = false;
        if (report(payload, "Scan finished")) window.location.reload();
      });
    });
  }
})();
