/* Android TV Dashboard - client.
 *
 * Three jobs, and nothing else:
 *   1. forward keys to the TV, but only while the remote panel has focus (design.md §4)
 *   2. turn the plain <form> POSTs into fetch() calls so a key press does not reload the page
 *   3. confirm the destructive actions, and fetch a screenshot on request
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

  /* The browser key names we forward, mapped to the server's aliases. Anything not in this
     map is left to the page, so Tab, F5 and the browser's own shortcuts still work. */
  var KEYS = {
    ArrowUp: "dpad_up",
    ArrowDown: "dpad_down",
    ArrowLeft: "dpad_left",
    ArrowRight: "dpad_right",
    Enter: "dpad_center",
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

  var active = false;
  var busy = false;

  function say(message, isError) {
    if (!state) return;
    state.textContent = message;
    state.classList.toggle("on", !!active);
    state.classList.toggle("error", !!isError);
  }

  function setActive(on) {
    active = !!on;
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
    setActive(document.activeElement === panel);
  }

  document.addEventListener("keydown", function (event) {
    if (!active) return;
    /* Esc releases the panel. It is never forwarded: design.md §4 makes it the way out. */
    if (event.key === "Escape") {
      if (panel) panel.blur();
      setActive(false);
      event.preventDefault();
      return;
    }
    /* Typing into a field of our own is typing, not remote control. */
    var tag = (event.target && event.target.tagName) || "";
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
    if (event.ctrlKey || event.metaKey || event.altKey) return;

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
    /* Sign-in and password changes set a cookie and move the browser; let them post normally. */
    if (action === "/api/login" || action === "/api/change_password") return;

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
      if (!report(payload, "Done")) return;
      if (RELOAD_AFTER[action]) window.location.reload();
    });
  });

  /* Actions that change what the page is showing. */
  var RELOAD_AFTER = {
    "/api/join": true,
    "/api/discover": true,
    "/api/uninstall": true,
    "/api/devices/use": true,
    "/api/devices/remove": true,
    "/api/devices/set_nickname": true
  };

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
