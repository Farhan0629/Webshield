/* =============================================================================
 *  WebShield AI - Permission Snooping Detector
 *  -----------------------------------------------------------------------------
 *  Watches for the current page actively *or* silently probing sensitive
 *  browser APIs (geolocation, microphone, camera, notifications, clipboard,
 *  enumerateDevices, MIDI, USB, screen wake lock, permissions query, etc.).
 *
 *  Why this matters:
 *    When a user has previously granted "Always allow" on a page, the page can
 *    silently read their location, listen on the mic, or watch through the
 *    camera WITHOUT showing a fresh permission prompt. The user has no idea
 *    it's happening. This detector surfaces that activity so the popup can
 *    warn them.
 *
 *  How it works:
 *    1. Static Analysis: Scans page script tags for code referencing sensitive APIs
 *       so threats are flagged immediately upon page load.
 *    2. Dynamic Analysis: Injects a main-world hook at document_start to catch
 *       live API calls (geolocation, mic, camera, clipboard, etc.) made by page JS,
 *       notifying content.js to update threat scores in real time.
 *
 *  Output:
 *    { score: 0..100, weight: 100, label: "Safe"|"Suspicious"|"Danger",
 *      findings: [...], permissions: { geolocation: n, microphone: n, ... } }
 * ============================================================================= */

(function () {
  "use strict";

  // Avoid double-installation when the script is re-injected on SPA nav.
  if (window.__webshield_perm_monitor_installed__) return;
  window.__webshield_perm_monitor_installed__ = true;

  /* ----------------------- Signal accumulator ------------------------- */
  const signals = {
    geolocation: 0,
    geolocationHighAccuracy: false,
    microphone: 0,
    camera: 0,
    enumerateDevices: 0,
    notifications: 0,
    clipboard: 0,
    midi: 0,
    usb: 0,
    wakeLock: 0,
    storageAccess: 0
  };

  /* ---------------- Event listener for Main World events -------------- */
  function handlePermEvent(detail) {
    if (!detail) return;
    switch (detail.type) {
      case "geolocation":
        signals.geolocation += 1;
        if (detail.highAccuracy) signals.geolocationHighAccuracy = true;
        break;
      case "getUserMedia":
        if (detail.audio) signals.microphone += 1;
        if (detail.video) signals.camera += 1;
        if (!detail.audio && !detail.video) {
          signals.microphone += 1;
        }
        break;
      case "enumerateDevices":
        signals.enumerateDevices += 1;
        break;
      case "notifications":
        signals.notifications += 1;
        break;
      case "clipboard":
        signals.clipboard += 1;
        break;
      case "midi":
        signals.midi += 1;
        break;
      case "usb":
        signals.usb += 1;
        break;
      case "wakeLock":
        signals.wakeLock += 1;
        break;
      case "permissionsQuery":
        if (detail.name === "camera") signals.camera += 1;
        else if (detail.name === "microphone") signals.microphone += 1;
        else if (detail.name === "geolocation") signals.geolocation += 1;
        else if (detail.name === "clipboard-read" || detail.name === "clipboard-write") signals.clipboard += 1;
        else signals.storageAccess += 1;
        break;
    }

    try {
      window.dispatchEvent(new CustomEvent("__webshield_rescan_needed__"));
    } catch (_) {}
  }

  window.addEventListener("__webshield_perm_event__", (evt) => {
    if (evt && evt.detail) handlePermEvent(evt.detail);
  });
  document.addEventListener("__webshield_perm_event__", (evt) => {
    if (evt && evt.detail) handlePermEvent(evt.detail);
  });

  /* ---------------- Main World Interceptor Injection ---------------- */
  function injectMainWorldHooks() {
    const script = document.createElement("script");
    script.setAttribute("data-webshield", "perm-hooks");
    script.textContent = `(${function mainWorldHook() {
      if (window.__webshield_main_perm_installed__) return;
      window.__webshield_main_perm_installed__ = true;

      function dispatchPermEvent(detail) {
        try {
          window.dispatchEvent(new CustomEvent("__webshield_perm_event__", { detail }));
          document.dispatchEvent(new CustomEvent("__webshield_perm_event__", { detail }));
        } catch (_) {}
      }

      // 1. Geolocation (getCurrentPosition & watchPosition)
      if (navigator.geolocation) {
        const origGet = navigator.geolocation.getCurrentPosition;
        if (typeof origGet === "function") {
          navigator.geolocation.getCurrentPosition = function (success, error, options) {
            const highAccuracy = !!(options && options.enableHighAccuracy);
            dispatchPermEvent({ type: "geolocation", highAccuracy });
            return origGet.apply(this, arguments);
          };
        }
        const origWatch = navigator.geolocation.watchPosition;
        if (typeof origWatch === "function") {
          navigator.geolocation.watchPosition = function (success, error, options) {
            const highAccuracy = !!(options && options.enableHighAccuracy);
            dispatchPermEvent({ type: "geolocation", highAccuracy });
            return origWatch.apply(this, arguments);
          };
        }
      }

      // 2. Microphone & Camera (MediaDevices & legacy getUserMedia)
      if (navigator.mediaDevices && typeof navigator.mediaDevices.getUserMedia === "function") {
        const origGUM = navigator.mediaDevices.getUserMedia;
        navigator.mediaDevices.getUserMedia = function (constraints) {
          const c = constraints || {};
          const audio = !!c.audio;
          const video = !!c.video;
          dispatchPermEvent({ type: "getUserMedia", audio, video });
          return origGUM.apply(this, arguments);
        };
      }
      if (typeof navigator.getUserMedia === "function") {
        const origLegacyGUM = navigator.getUserMedia;
        navigator.getUserMedia = function (constraints, success, error) {
          const c = constraints || {};
          const audio = !!c.audio;
          const video = !!c.video;
          dispatchPermEvent({ type: "getUserMedia", audio, video });
          return origLegacyGUM.apply(this, arguments);
        };
      }

      // 3. Device Enumeration
      if (navigator.mediaDevices && typeof navigator.mediaDevices.enumerateDevices === "function") {
        const origEnum = navigator.mediaDevices.enumerateDevices;
        navigator.mediaDevices.enumerateDevices = function () {
          dispatchPermEvent({ type: "enumerateDevices" });
          return origEnum.apply(this, arguments);
        };
      }

      // 4. Notifications
      if (window.Notification && typeof window.Notification.requestPermission === "function") {
        const origNotif = window.Notification.requestPermission;
        window.Notification.requestPermission = function () {
          dispatchPermEvent({ type: "notifications" });
          return origNotif.apply(this, arguments);
        };
      }

      // 5. Clipboard
      if (navigator.clipboard) {
        ["readText", "read"].forEach(method => {
          if (typeof navigator.clipboard[method] === "function") {
            const origClip = navigator.clipboard[method];
            navigator.clipboard[method] = function () {
              dispatchPermEvent({ type: "clipboard" });
              return origClip.apply(this, arguments);
            };
          }
        });
      }

      // 6. MIDI Access
      if (typeof navigator.requestMIDIAccess === "function") {
        const origMIDI = navigator.requestMIDIAccess;
        navigator.requestMIDIAccess = function () {
          dispatchPermEvent({ type: "midi" });
          return origMIDI.apply(this, arguments);
        };
      }

      // 7. USB Devices
      if (navigator.usb && typeof navigator.usb.requestDevice === "function") {
        const origUSB = navigator.usb.requestDevice;
        navigator.usb.requestDevice = function () {
          dispatchPermEvent({ type: "usb" });
          return origUSB.apply(this, arguments);
        };
      }

      // 8. Screen Wake Lock
      if (navigator.wakeLock && typeof navigator.wakeLock.request === "function") {
        const origWake = navigator.wakeLock.request;
        navigator.wakeLock.request = function () {
          dispatchPermEvent({ type: "wakeLock" });
          return origWake.apply(this, arguments);
        };
      }

      // 9. Permissions API Query
      if (navigator.permissions && typeof navigator.permissions.query === "function") {
        const origPermQuery = navigator.permissions.query;
        navigator.permissions.query = function (desc) {
          try {
            const name = desc && desc.name;
            dispatchPermEvent({ type: "permissionsQuery", name });
          } catch (_) {}
          return origPermQuery.apply(this, arguments);
        };
      }
    }})()`;

    try {
      const parent = document.head || document.documentElement;
      if (parent) {
        parent.appendChild(script);
        script.remove();
      }
    } catch (_) {}
  }

  function tryInject() {
    const parent = document.head || document.documentElement;
    if (parent) {
      injectMainWorldHooks();
      return true;
    }
    return false;
  }

  if (!tryInject()) {
    const observer = new MutationObserver(() => {
      if (tryInject()) observer.disconnect();
    });
    observer.observe(document, { childList: true, subtree: true });
    document.addEventListener("DOMContentLoaded", tryInject, { once: true });
  }

  /* ---------------- Static Script Analysis ------------------ */
  function scanStaticScripts() {
    const staticSignals = {
      geolocation: 0,
      microphone: 0,
      camera: 0,
      clipboard: 0,
      notifications: 0,
      enumerateDevices: 0,
      midi: 0,
      usb: 0,
      wakeLock: 0
    };

    try {
      const scripts = document.querySelectorAll("script");
      scripts.forEach(s => {
        const text = s.textContent || "";
        if (!text.trim()) return;

        if (/navigator\.geolocation|\.getCurrentPosition|\.watchPosition/i.test(text)) {
          staticSignals.geolocation++;
        }
        if (/navigator\.clipboard|\.readText\b/i.test(text)) {
          staticSignals.clipboard++;
        }
        if (/getUserMedia\b/i.test(text)) {
          if (/audio\s*:\s*true/i.test(text)) staticSignals.microphone++;
          if (/video\s*:\s*true/i.test(text)) staticSignals.camera++;
          if (!/audio|video/i.test(text)) staticSignals.microphone++;
        }
        if (/Notification\.requestPermission/i.test(text)) {
          staticSignals.notifications++;
        }
        if (/enumerateDevices/i.test(text)) {
          staticSignals.enumerateDevices++;
        }
        if (/requestMIDIAccess/i.test(text)) {
          staticSignals.midi++;
        }
        if (/requestDevice\b/i.test(text) && /usb/i.test(text)) {
          staticSignals.usb++;
        }
        if (/wakeLock\.request/i.test(text)) {
          staticSignals.wakeLock++;
        }
      });
    } catch (_) {}

    return staticSignals;
  }

  /* ----------------------- run() ------------------------------------- */
  function run() {
    const findings = [];
    let score = 0;

    const staticSignals = scanStaticScripts();

    const effectiveGeo = Math.max(signals.geolocation, staticSignals.geolocation);
    const effectiveMic = Math.max(signals.microphone, staticSignals.microphone);
    const effectiveCam = Math.max(signals.camera, staticSignals.camera);
    const effectiveClip = Math.max(signals.clipboard, staticSignals.clipboard);
    const effectiveNotif = Math.max(signals.notifications, staticSignals.notifications);
    const effectiveEnum = Math.max(signals.enumerateDevices, staticSignals.enumerateDevices);
    const effectiveMidi = Math.max(signals.midi, staticSignals.midi);
    const effectiveUsb = Math.max(signals.usb, staticSignals.usb);
    const effectiveWake = Math.max(signals.wakeLock, staticSignals.wakeLock);

    if (effectiveGeo > 0) {
      const flag = signals.geolocationHighAccuracy ? " (high-accuracy)" : "";
      const source = signals.geolocation > 0 ? "accessed" : "code probe detected";
      findings.push(`Geolocation ${source} ${effectiveGeo}×${flag}`);
      score += Math.min(70, effectiveGeo * 35 + (signals.geolocationHighAccuracy ? 15 : 0));
    }
    if (effectiveMic > 0) {
      const source = signals.microphone > 0 ? "requested" : "code probe detected";
      findings.push(`Microphone ${source} ${effectiveMic}×`);
      score += Math.min(80, effectiveMic * 40);
    }
    if (effectiveCam > 0) {
      const source = signals.camera > 0 ? "requested" : "code probe detected";
      findings.push(`Camera ${source} ${effectiveCam}×`);
      score += Math.min(80, effectiveCam * 40);
    }
    if (effectiveNotif > 0) {
      findings.push(`Notification permission requested/code ${effectiveNotif}×`);
      score += Math.min(25, effectiveNotif * 12);
    }
    if (effectiveClip > 0) {
      const source = signals.clipboard > 0 ? "read" : "code probe detected";
      findings.push(`Clipboard ${source} ${effectiveClip}×`);
      score += Math.min(30, effectiveClip * 12);
    }
    if (effectiveEnum > 0) {
      findings.push(`enumerateDevices() called/code ${effectiveEnum}×`);
      score += Math.min(25, effectiveEnum * 8);
    }
    if (effectiveMidi > 0) {
      findings.push(`MIDI access requested/code ${effectiveMidi}×`);
      score += Math.min(18, effectiveMidi * 9);
    }
    if (effectiveUsb > 0) {
      findings.push(`USB device picker code/access ${effectiveUsb}×`);
      score += Math.min(18, effectiveUsb * 9);
    }
    if (effectiveWake > 0) {
      findings.push(`Wake lock code/access ${effectiveWake}×`);
      score += Math.min(12, effectiveWake * 6);
    }

    const distinctTouched = [
      effectiveGeo, effectiveMic, effectiveCam,
      effectiveNotif, effectiveClip, effectiveEnum,
      effectiveMidi, effectiveUsb, effectiveWake
    ].filter(n => n > 0).length;

    if (distinctTouched >= 3) {
      findings.push(`Page probed ${distinctTouched} different sensitive APIs`);
      score += 15;
    }

    score = Math.max(0, Math.min(100, Math.round(score)));

    let label = "Safe";
    if (score >= 55) label = "Danger";
    else if (score >= 20) label = "Suspicious";

    const reportedPerms = {
      geolocation: effectiveGeo,
      microphone: effectiveMic,
      camera: effectiveCam,
      notifications: effectiveNotif,
      clipboard: effectiveClip,
      enumerateDevices: effectiveEnum,
      midi: effectiveMidi,
      usb: effectiveUsb,
      wakeLock: effectiveWake,
      storageAccess: signals.storageAccess
    };

    return { score, weight: 100, label, findings, permissions: reportedPerms };
  }

  window.WebShieldDetectors = window.WebShieldDetectors || {};
  window.WebShieldDetectors.permissionSnooper = { run, signals };
})();


