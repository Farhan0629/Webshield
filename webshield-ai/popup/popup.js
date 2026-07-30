(function () {
  "use strict";

  const el = {
    currentUrl:     document.getElementById("currentUrl"),
    statusBanner:   document.getElementById("statusBanner"),
    statusIcon:     document.getElementById("statusIcon"),
    statusText:     document.getElementById("statusText"),
    flaggedCount:   document.getElementById("flaggedCount"),
    recList:        document.getElementById("recList"),
    scriptsTotal:   document.getElementById("scriptsTotal"),
    scriptsSusp:    document.getElementById("scriptsSuspicious"),
    lastScan:       document.getElementById("lastScan"),
    scanBtn:        document.getElementById("scanBtn"),
    dismissBtn:     document.getElementById("dismissBtn"),
    sensorPanel:    document.getElementById("sensorPanel"),
    sensorChips:    document.getElementById("sensorChips"),
    diagList:       document.getElementById("diagList"),
    sbStatus:       document.getElementById("sbStatus"),
    sbDetails:      document.getElementById("sbDetails"),
    sbMatchList:    document.getElementById("sbMatchList"),
    settingsBtn:    document.getElementById("settingsBtn"),
    trustCheckbox:  document.getElementById("trustCheckbox"),
    cards:          Array.from(document.querySelectorAll(".threat-card"))
  };

  const SENSOR_DEFS = [
    { key: "geolocation",       label: "Location",  live: true  },
    { key: "microphone",        label: "Microphone",live: true  },
    { key: "camera",            label: "Camera",    live: true  },
    { key: "notifications",     label: "Notifications", live: false },
    { key: "clipboard",         label: "Clipboard", live: false },
    { key: "enumerateDevices",  label: "Devices",   live: false },
    { key: "midi",              label: "MIDI",      live: false },
    { key: "usb",               label: "USB",       live: false },
    { key: "wakeLock",          label: "Wake Lock", live: false }
  ];

  function statusClass(label) {
    if (label === "Danger")     return "status-danger";
    if (label === "Suspicious") return "status-suspicious";
    return "status-safe";
  }

  function renderSensors(permissions) {
    el.sensorChips.innerHTML = "";
    const perms = permissions || {};
    let touched = 0;

    SENSOR_DEFS.forEach(def => {
      const count = perms[def.key];
      if (!count || count <= 0) return;
      touched++;

      const chip = document.createElement("div");
      chip.className = "sensor-chip" + (def.live ? " live" : "");

      const label = document.createElement("span");
      label.className = "chip-label";
      label.textContent = def.label + (def.live ? " (live)" : "");

      const countEl = document.createElement("span");
      countEl.className = "chip-count";
      countEl.textContent = String(count);

      chip.appendChild(label);
      chip.appendChild(countEl);
      el.sensorChips.appendChild(chip);
    });

    el.sensorPanel.hidden = touched === 0;
  }

  function renderDiag(diag) {
    el.diagList.innerHTML = "";
    if (!Array.isArray(diag) || diag.length === 0) {
      const empty = document.createElement("div");
      empty.className = "diag-row";
      empty.innerHTML = '<span class="diag-empty">No scan yet.</span>';
      el.diagList.appendChild(empty);
      return;
    }
    diag.forEach(d => {
      const row = document.createElement("div");
      row.className = "diag-row";
      const name = document.createElement("span");
      name.className = "diag-name";
      name.textContent = d.name;
      const meta = document.createElement("span");
      meta.className = "diag-meta";
      const score = document.createElement("span");
      score.className = "diag-score";
      score.textContent = String(d.score) + "/100";
      const label = document.createElement("span");
      label.className = "diag-label " + (d.label || "Safe");
      label.textContent = d.label || "Safe";
      meta.appendChild(score);
      meta.appendChild(label);
      row.appendChild(name);
      row.appendChild(meta);
      el.diagList.appendChild(row);
    });
  }

  function formatTime(ts) {
    if (!ts) return "&mdash;";
    try {
      const d = new Date(ts);
      const pad = (n) => String(n).padStart(2, "0");
      return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
    } catch (_) { return "&mdash;"; }
  }

  function shortenUrl(u) {
    if (!u) return "&mdash;";
    try {
      const parsed = new URL(u);
      return parsed.hostname + (parsed.pathname !== "/" ? parsed.pathname : "");
    } catch (_) {
      return u.length > 30 ? u.slice(0, 14) + "..." + u.slice(-12) : u;
    }
  }

  function getHostname(url) {
    try { return new URL(url).hostname; } catch (_) { return ""; }
  }

  /**
   * Determine banner tone based on flagged count and safe browsing verdict.
   */
  function bannerTone(flaggedCount, totalDetectors, sbVerdict, sbMatches) {
    if (sbVerdict === "malicious" && sbMatches && sbMatches.length > 0) return "critical";
    if (flaggedCount >= 2)         return "danger";
    if (flaggedCount === 1)        return "warning";
    return "safe";
  }

  /**
   * Update the trust checkbox state for the current URL.
   */
  function checkTrustStatus(url) {
    const hostname = getHostname(url);
    if (!hostname) { el.trustCheckbox.checked = false; return; }
    chrome.runtime.sendMessage({ type: "IS_TRUSTED", hostname }, (resp) => {
      el.trustCheckbox.checked = !!(resp && resp.trusted);
    });
  }

  /**
   * Build SVG icon for the status banner.
   */
  function statusIconSVG(tone) {
    if (tone === "safe") {
      return '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L3 5v7c0 5 3.8 9.4 9 10 5.2-.6 9-5 9-10V5l-9-3z"/><path d="M9 12.5l2 2 4-4"/></svg>';
    }
    return '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
  }

  /**
   * Render the full scan result into the popup UI.
   */
  function render(payload, fallbackUrl) {
    if (!payload) {
      el.statusText.textContent = "Scanning...";
      el.statusBanner.className = "status-banner";
      el.flaggedCount.textContent = "";
      el.currentUrl.textContent = shortenUrl(fallbackUrl || "");
      el.sensorPanel.hidden = true;
      if (el.sbStatus) { el.sbStatus.textContent = ""; el.sbStatus.className = "sb-status"; }
      if (el.sbDetails) el.sbDetails.hidden = true;
      return;
    }

    el.currentUrl.textContent = shortenUrl(payload.url || fallbackUrl || "");
    el.currentUrl.title = payload.url || fallbackUrl || "";

    const flagged = payload.flaggedCount || 0;
    const total = payload.totalDetectors || 8;
    const sbVerdict = payload.safeBrowsing || "unchecked";
    const sbMatches = payload.sbMatches || [];
    const tone = bannerTone(flagged, total, sbVerdict, sbMatches);

    // Status banner
    el.statusIcon.innerHTML = statusIconSVG(tone);
    el.statusBanner.className = "status-banner tone-" + tone;

    const toneLabels = { safe: "All Clear", warning: "Caution", danger: "Warning", critical: "Critical" };
    el.statusText.textContent = toneLabels[tone] || "All Clear";

    // Flagged count line
    if (tone === "safe") {
      el.flaggedCount.textContent = "0 of " + total + " detectors flagged";
      el.flaggedCount.className = "flagged-count fc-safe";
    } else {
      el.flaggedCount.textContent = flagged + " of " + total + " detectors flagged";
      el.flaggedCount.className = "flagged-count fc-" + tone;
    }

    // Threat cards
    const threats = payload.threats || {};
    el.cards.forEach(card => {
      const key = card.getAttribute("data-key");
      const label = threats[key] || "Safe";
      const status = card.querySelector(".card-status");
      status.textContent = label;
      status.className = "card-status " + statusClass(label);
    });

    // Recommendations
    const recs = payload.recommendations || ["This page appears safe."];
    el.recList.innerHTML = "";
    recs.forEach(text => {
      const li = document.createElement("li");
      li.className = "rec-item";
      li.textContent = text;
      el.recList.appendChild(li);
    });

    // Stats
    const stats = payload.scriptStats || { total: 0, suspicious: 0 };
    el.scriptsTotal.textContent = String(stats.total);
    el.scriptsSusp.textContent  = String(stats.suspicious);

    // Sensor panel
    renderSensors(payload.permissions);

    // Per-detector diagnostic
    renderDiag(payload.diag);

    // Safe Browsing verdict
    renderSafeBrowsing(payload.safeBrowsing, payload.sbMatches);

    // Timestamp
    el.lastScan.textContent = formatTime(payload.timestamp);

    // Trust toggle
    checkTrustStatus(payload.url);
  }

  function renderSafeBrowsing(verdict, matches) {
    if (!el.sbStatus) return;

    if (verdict === "malicious" && Array.isArray(matches) && matches.length > 0) {
      const threatTypes = [...new Set(matches.map(m => m.threatType))];
      el.sbStatus.textContent = "Flagged by Google Safe Browsing: " + threatTypes.join(", ");
      el.sbStatus.className = "sb-status sb-malicious";

      // Show match details.
      el.sbDetails.hidden = false;
      el.sbMatchList.innerHTML = "";
      matches.forEach(m => {
        const row = document.createElement("div");
        row.className = "sb-match-row";
        row.innerHTML = '<span class="sb-match-type">' + (m.threatType || "unknown") + '</span> <span class="sb-match-url">' + (m.threat && m.threat.url ? shortenUrl(m.threat.url) : "") + '</span>';
        el.sbMatchList.appendChild(row);
      });
    } else if (verdict === "clean") {
      el.sbStatus.textContent = "No known threats (Google Safe Browsing)";
      el.sbStatus.className = "sb-status sb-clean";
      el.sbDetails.hidden = true;
    } else {
      el.sbStatus.textContent = "Google Safe Browsing not checked";
      el.sbStatus.className = "sb-status sb-unchecked";
      el.sbDetails.hidden = true;
    }
  }

  function fetchLatest() {
    chrome.runtime.sendMessage({ type: "GET_LATEST_SCAN" }, (resp) => {
      if (!resp) {
        render(null, "");
        return;
      }
      if (resp.scanning) {
        render(null, resp.url || "");
      } else if (resp.payload) {
        render(resp.payload, resp.url || "");
      } else {
        render(null, resp.url || "");
      }
    });
  }

  function refreshScan() {
    el.scanBtn.disabled = true;
    el.scanBtn.innerHTML = '<span class="btn-icon">&olarr;</span><span>Scanning...</span>';
    chrome.runtime.sendMessage({ type: "REFRESH_SCAN" }, () => {
      setTimeout(() => {
        fetchLatest();
        el.scanBtn.disabled = false;
        el.scanBtn.innerHTML = '<span class="btn-icon">&olarr;</span><span>Refresh Scan</span>';
      }, 1200);
    });
  }

  // Trust toggle handler
  el.trustCheckbox.addEventListener("change", () => {
    const urlEl = el.currentUrl;
    const hostname = getHostname(urlEl.title || urlEl.textContent);
    if (!hostname) return;
    chrome.runtime.sendMessage({ type: "TOGGLE_TRUST", hostname }, (resp) => {
      if (resp && resp.ok) {
        el.trustCheckbox.checked = resp.trusted;
        if (resp.trusted) {
          render({
            url: urlEl.title,
            flaggedCount: 0,
            totalDetectors: 8,
            threats: {},
            recommendations: ["Site is trusted. Scanning is skipped."],
            scriptStats: { total: 0, suspicious: 0 },
            permissions: {},
            diag: [],
            safeBrowsing: "unchecked",
            timestamp: Date.now()
          });
        } else {
          refreshScan();
        }
      }
    });
  });

  let alreadyRendered = false;
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "SCAN_CACHED" && msg.payload) {
      alreadyRendered = true;
      render(msg.payload, msg.payload.url);
    }
  });

  el.scanBtn.addEventListener("click", refreshScan);
  el.dismissBtn.addEventListener("click", () => window.close());
  if (el.settingsBtn) {
    el.settingsBtn.addEventListener("click", () => chrome.runtime.openOptionsPage());
  }

  fetchLatest();
  let attempts = 0;
  const iv = setInterval(() => {
    if (alreadyRendered) { clearInterval(iv); return; }
    attempts++;
    fetchLatest();
    if (attempts >= 6) clearInterval(iv);
  }, 700);

})();
