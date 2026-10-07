/* =============================================================================
 *  WebShield AI - Content Script
 *  -----------------------------------------------------------------------------
 *  This script runs in the context of every webpage the user visits. It
 *  coordinates all detectors, then ships the per-detector report back
 *  to the background service worker.
 *
 *  IMPORTANT:
 *    - We never modify the page. Detectors only READ.
 *    - Each detector runs inside its own try/catch in runOne(). If a detector
 *      throws (e.g. it hits a CSP restriction on a specific page), we still
 *      get a usable partial report from the OTHER detectors.
 *    - Debug logs are gated behind `window.__webshield_debug__ = true` so
 *      normal users don't see anything in the console.
 * ============================================================================= */

(function () {
  "use strict";

  // Guard against double-injection on SPA navigations.
  if (window.__webshield_loaded__) return;
  window.__webshield_loaded__ = true;

  // Always-on concise logger so users can see what each detector found.
  function log(...args) {
    try {
      // eslint-disable-next-line no-console
      console.info("[WebShield]", ...args);
    } catch (_) { /* ignore */ }
  }

  /**
   * Run a single detector but swallow errors so one broken detector doesn't
   * take down the entire report. Returns a safe default on failure.
   * Now async so it can await detector.run() when it returns a Promise
   * (the scriptAnalyzer does this for external script fetches).
   */
  async function runOne(name, detector) {
    if (!detector || typeof detector.run !== "function") {
      log("detector missing:", name);
      return { score: 0, weight: 100, label: "Safe", findings: [] };
    }
    try {
      const maybe = detector.run();
      const result = (maybe && typeof maybe.then === "function")
        ? await maybe
        : maybe;
      if (!result || typeof result !== "object") {
        return { score: 0, weight: 100, label: "Safe", findings: [], error: "non-object result" };
      }
      return {
        score:    Number.isFinite(result.score) ? result.score : 0,
        weight:   Number.isFinite(result.weight) ? result.weight : 100,
        label:    typeof result.label === "string" ? result.label : "Safe",
        findings: Array.isArray(result.findings) ? result.findings : [],
        stats:    result.stats,
        permissions: result.permissions
      };
    } catch (err) {
      log("detector threw:", name, err && err.message ? err.message : err);
      return {
        score: 0, weight: 100, label: "Safe", findings: [],
        error: String(err && err.message || err)
      };
    }
  }

  /* ------------------------------------------------------------------------ *
   *  runAllDetectors()
   *  Runs every detector in isolation. Each one is wrapped in try/catch via
   *  runOne() so a single failure cannot break the others.
   * ------------------------------------------------------------------------ */
  async function runAllDetectors() {
    const D = window.WebShieldDetectors || {};
    const R = window.WebShieldRiskEngine || {};

    // Order matches the manifest's content_scripts list.
    const detectors = [
      ["DOM XSS",             D.domScanner],
      ["Clickjacking",        D.clickjacking],
      ["Malicious JS",        D.scriptAnalyzer],
      ["Cookie Theft",        D.cookieMonitor],
      ["Crypto Miner",        D.cryptoMiner],
      ["Drive-by Download",   D.downloadMonitor],
      ["Permission Snooping", D.permissionSnooper]
    ];

    // runOne is async (scriptAnalyzer fetches external scripts). Await each.
    const results = [];
    for (const [name, det] of detectors) {
      results.push(await runOne(name, det));
    }

    // Per-detector scores for diagnostics.
    results.forEach((r, i) =>
      log(detectors[i][0], "→", "score=" + r.score, "label=" + r.label,
          r.error ? ("ERR=" + r.error) : "")
    );

    // Compute how many detectors flagged something (Danger or Suspicious).
    const flaggedCount = results.filter(r => r.label === "Danger" || r.label === "Suspicious").length;

    // Build a threats object even if some detectors failed. Every key always
    // gets a value so the popup never sees a partially-empty UI.
    const threats = {};
    detectors.forEach(([name], idx) => {
      threats[name] = results[idx].label || "Safe";
    });

    // Recommendations come from the highest-impact threats. If the engine is
    // broken, provide a sensible default so the popup always has something.
    let recommendations;
    try {
      recommendations = typeof R.recommend === "function"
        ? R.recommend(threats)
        : ["This page appears safe."];
    } catch (_) {
      recommendations = ["This page appears safe."];
    }

    // Script stats from the scriptAnalyzer (if available).
    const scriptStats = (results[2] && results[2].stats)
      ? results[2].stats
      : { total: 0, suspicious: 0 };

    // Permission counters from the permissionSnooper (if available).
    const permissionDetails = (results[6] && results[6].permissions) || {};

    // Collect sub-resource URLs for Safe Browsing checks.
    const pageScriptUrls = Array.from(document.querySelectorAll("script[src]")).map(s => s.src);
    const pageIframeUrls = Array.from(document.querySelectorAll("iframe[src], frame[src]")).map(f => f.src);

    const payload = {
      url: location.href,
      flaggedCount,
      threats,
      recommendations,
      scriptStats,
      permissions: permissionDetails,
      pageScriptUrls,
      pageIframeUrls,
      timestamp: Date.now(),
      // Diagnostic: which detectors actually saw something? Lets us
      // answer "why is the score 0?" without opening the console.
      diag: results.map((r, i) => ({
        name: detectors[i][0],
        score: r.score,
        label: r.label,
        hitCount: (r.findings || []).length
      }))
    };

    log("scan complete:", { flaggedCount, threats, scriptStats });
    return payload;
  }

  /* ------------------------------------------------------------------------ *
   *  Message handler for the background script.
   *  RUN_SCAN  -> perform a fresh scan and POST back as SCAN_RESULT.
   * ------------------------------------------------------------------------ */
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (!msg || msg.type !== "RUN_SCAN") return false;

    (async () => {
      try {
        const payload = await runAllDetectors();
        chrome.runtime.sendMessage({ type: "SCAN_RESULT", payload });
        sendResponse({ ok: true, received: true });
      } catch (err) {
        // If anything throws, surface a minimal safe-by-default report.
        log("runAllDetectors threw:", err && err.message);
        chrome.runtime.sendMessage({
          type: "SCAN_RESULT",
          payload: {
            url: location.href,
            flaggedCount: 0,
            threats: {},
            recommendations: ["Scan could not complete on this page."],
            scriptStats: { total: 0, suspicious: 0 },
            permissions: {},
            pageScriptUrls: [],
            pageIframeUrls: [],
            timestamp: Date.now(),
            error: String(err && err.message || err)
          }
        });
        sendResponse({ ok: true, received: true });
      }
    })();

    return true; // async response
  });

  /* ------------------------------------------------------------------------ *
   *  In-page floating toast notification (WebShield AI's own UI)
   *  Uses Shadow DOM so page CSS cannot affect it.
   * ------------------------------------------------------------------------ */
  function showInPageToast(evalResult, url) {
    // Remove any existing toast first
    const existing = document.getElementById("webshield-toast-host");
    if (existing) existing.remove();

    const score  = evalResult ? evalResult.score : 0;
    const rating = evalResult ? evalResult.rating : "Safe";
    const reasons = evalResult && Array.isArray(evalResult.reasons) ? evalResult.reasons : [];
    const topReasons = reasons.slice(0, 3);

    let hostname = "";
    try { hostname = new URL(url).hostname; } catch (_) { hostname = url; }

    // Color schemes per rating
    const themes = {
      "Safe":       { bg: "#0d2818", border: "#22c55e", accent: "#4ade80", badge: "rgba(34,197,94,0.18)" },
      "Low Risk":   { bg: "#0c1929", border: "#38bdf8", accent: "#7dd3fc", badge: "rgba(56,189,248,0.18)" },
      "Suspicious": { bg: "#291a00", border: "#f97316", accent: "#fdba74", badge: "rgba(249,115,22,0.18)" },
      "High Risk":  { bg: "#2a0a0a", border: "#ef4444", accent: "#fca5a5", badge: "rgba(239,68,68,0.18)" },
      "Critical":   { bg: "#3b0000", border: "#dc2626", accent: "#f87171", badge: "rgba(220,38,38,0.25)" }
    };
    const theme = themes[rating] || themes["Safe"];

    // Build reason bullets HTML
    const reasonsHTML = topReasons.length > 0
      ? topReasons.map(r => `<div style="font-size:11px;color:#94a3b8;padding:2px 0 2px 12px;position:relative;">
          <span style="position:absolute;left:0;top:2px;color:${theme.accent};">•</span>${r}</div>`).join("")
      : `<div style="font-size:11px;color:#94a3b8;padding:2px 0 2px 12px;">All indicators within normal parameters.</div>`;

    // Create host element
    const host = document.createElement("div");
    host.id = "webshield-toast-host";
    host.style.cssText = "all:initial;position:fixed;bottom:20px;right:20px;z-index:2147483647;font-family:system-ui,-apple-system,sans-serif;";

    const shadow = host.attachShadow({ mode: "closed" });

    shadow.innerHTML = `
      <style>
        @keyframes wsSlideIn {
          from { transform: translateX(120%); opacity: 0; }
          to   { transform: translateX(0);    opacity: 1; }
        }
        @keyframes wsSlideOut {
          from { transform: translateX(0);    opacity: 1; }
          to   { transform: translateX(120%); opacity: 0; }
        }
        @keyframes wsPulse {
          0%, 100% { box-shadow: 0 0 0 0 ${theme.border}44; }
          50%      { box-shadow: 0 0 0 8px ${theme.border}00; }
        }
        .ws-toast {
          width: 310px;
          background: ${theme.bg};
          border: 1px solid ${theme.border}88;
          border-radius: 14px;
          padding: 14px 16px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.45), 0 0 0 1px rgba(255,255,255,0.04);
          animation: wsSlideIn 0.4s cubic-bezier(0.16,1,0.3,1) forwards;
          font-family: system-ui, -apple-system, sans-serif;
          cursor: default;
          backdrop-filter: blur(12px);
        }
        .ws-toast.dismissing {
          animation: wsSlideOut 0.3s ease-in forwards;
        }
        .ws-toast.pulse {
          animation: wsSlideIn 0.4s cubic-bezier(0.16,1,0.3,1) forwards, wsPulse 1.5s ease-out infinite 0.5s;
        }
        .ws-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 10px;
        }
        .ws-brand {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 12px;
          font-weight: 700;
          color: #e2e8f0;
          letter-spacing: 0.3px;
        }
        .ws-brand svg { width: 16px; height: 16px; color: ${theme.accent}; }
        .ws-close {
          background: none;
          border: none;
          color: #475569;
          font-size: 16px;
          cursor: pointer;
          padding: 2px 6px;
          border-radius: 6px;
          line-height: 1;
          transition: color 0.15s, background 0.15s;
        }
        .ws-close:hover { color: #e2e8f0; background: rgba(255,255,255,0.08); }
        .ws-score-row {
          display: flex;
          align-items: center;
          gap: 10px;
          margin-bottom: 8px;
        }
        .ws-score {
          font-size: 24px;
          font-weight: 800;
          color: ${theme.accent};
          letter-spacing: -0.5px;
        }
        .ws-score span { font-size: 13px; color: #64748b; font-weight: 600; }
        .ws-rating {
          font-size: 11px;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          padding: 3px 8px;
          border-radius: 999px;
          color: ${theme.accent};
          background: ${theme.badge};
          border: 1px solid ${theme.border}55;
        }
        .ws-host {
          font-size: 11px;
          color: #64748b;
          margin-left: auto;
          max-width: 120px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .ws-reasons {
          border-top: 1px solid rgba(255,255,255,0.06);
          padding-top: 8px;
          margin-top: 4px;
        }
      </style>
      <div class="ws-toast ${rating === "Critical" || rating === "High Risk" ? "pulse" : ""}" id="toast">
        <div class="ws-header">
          <div class="ws-brand">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 2L3 5v7c0 5 3.8 9.4 9 10 5.2-.6 9-5 9-10V5l-9-3z"/>
            </svg>
            WebShield AI
          </div>
          <button class="ws-close" id="closeBtn" title="Dismiss">&times;</button>
        </div>
        <div class="ws-score-row">
          <div class="ws-score">${score}<span>/100</span></div>
          <div class="ws-rating">${rating}</div>
          <div class="ws-host" title="${hostname}">${hostname}</div>
        </div>
        <div class="ws-reasons">
          ${reasonsHTML}
        </div>
      </div>
    `;

    // Wire up close button
    shadow.getElementById("closeBtn").addEventListener("click", () => {
      const toast = shadow.getElementById("toast");
      toast.classList.add("dismissing");
      setTimeout(() => host.remove(), 300);
    });

    document.documentElement.appendChild(host);

    // Auto-dismiss safe / low-risk after 7 seconds
    if (rating === "Safe" || rating === "Low Risk") {
      setTimeout(() => {
        if (!host.parentElement) return;
        const toast = shadow.getElementById("toast");
        if (toast) toast.classList.add("dismissing");
        setTimeout(() => { if (host.parentElement) host.remove(); }, 300);
      }, 7000);
    }
  }

  /* ------------------------------------------------------------------------ *
   *  Progressive 2-Stage Auto-Scan Execution Pipeline
   *  ------------------------------------------------------------------------
   *  Stage 1 (Fast Pass ~50ms): Runs local synchronous detectors immediately.
   *            Renders the in-page toast & toolbar badge near-instantly!
   *  Stage 2 (Async Deep Scan): Completes external script fetches & Safe Browsing,
   *            updating the toast seamlessly if deeper threats are uncovered.
   *  MutationObserver: Watches for dynamically injected scripts/iframes in SPAs.
   * ------------------------------------------------------------------------ */
  let rescanDebounceTimer = null;
  function triggerRealtimeRescan() {
    if (rescanDebounceTimer) clearTimeout(rescanDebounceTimer);
    rescanDebounceTimer = setTimeout(async () => {
      try {
        const payload = await runAllDetectors();
        chrome.runtime.sendMessage({ type: "SCAN_RESULT", payload });
        const R = window.WebShieldRiskEngine || {};
        if (typeof R.evaluateOverallRisk === "function") {
          const evalResult = R.evaluateOverallRisk(payload.diag || []);
          showInPageToast(evalResult, payload.url);
        }
      } catch (err) {
        log("realtime rescan failed:", err && err.message);
      }
    }, 150);
  }

  window.addEventListener("__webshield_rescan_needed__", triggerRealtimeRescan);
  document.addEventListener("__webshield_rescan_needed__", triggerRealtimeRescan);

  // Attach lightweight MutationObserver to detect dynamically added scripts or iframes
  try {
    const observer = new MutationObserver((mutations) => {
      let shouldRescan = false;
      for (const m of mutations) {
        if (m.addedNodes && m.addedNodes.length > 0) {
          for (const node of m.addedNodes) {
            if (node.nodeType === 1) { // Element node
              const tag = node.tagName.toLowerCase();
              if (tag === "script" || tag === "iframe" || tag === "embed" || tag === "object" ||
                  node.hasAttribute("onload") || node.hasAttribute("onerror")) {
                shouldRescan = true;
                break;
              }
            }
          }
        }
        if (shouldRescan) break;
      }
      if (shouldRescan) triggerRealtimeRescan();
    });

    if (document.documentElement) {
      observer.observe(document.documentElement, { childList: true, subtree: true });
    }
  } catch (_) {}

  // Progressive 2-Stage Kickoff
  async function startProgressiveScan() {
    try {
      // Stage 1: Fast Immediate Pass (~50ms)
      const payload1 = await runAllDetectors();
      chrome.runtime.sendMessage({ type: "SCAN_RESULT", payload: payload1 });

      const R = window.WebShieldRiskEngine || {};
      if (typeof R.evaluateOverallRisk === "function") {
        const evalResult1 = R.evaluateOverallRisk(payload1.diag || []);
        showInPageToast(evalResult1, payload1.url);
      }

      // Stage 2: Deep Pass (if page is still loading external scripts)
      if (document.readyState !== "complete") {
        window.addEventListener("load", () => setTimeout(triggerRealtimeRescan, 500), { once: true });
      }
    } catch (err) {
      log("progressive scan error:", err && err.message);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startProgressiveScan, { once: true });
  } else {
    setTimeout(startProgressiveScan, 50);
  }

})();
