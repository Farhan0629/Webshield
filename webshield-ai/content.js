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
   *  Auto-scan on initial injection & listener for real-time rescan events.
   * ------------------------------------------------------------------------ */
  let rescanDebounceTimer = null;
  function triggerRealtimeRescan() {
    if (rescanDebounceTimer) clearTimeout(rescanDebounceTimer);
    rescanDebounceTimer = setTimeout(async () => {
      try {
        const payload = await runAllDetectors();
        chrome.runtime.sendMessage({ type: "SCAN_RESULT", payload });
      } catch (err) {
        log("realtime rescan failed:", err && err.message);
      }
    }, 100);
  }

  window.addEventListener("__webshield_rescan_needed__", triggerRealtimeRescan);
  document.addEventListener("__webshield_rescan_needed__", triggerRealtimeRescan);

  const initialDelay = document.readyState === "complete" ? 250 : 1500;
  setTimeout(() => {
    (async () => {
      try {
        const payload = await runAllDetectors();
        chrome.runtime.sendMessage({ type: "SCAN_RESULT", payload });
      } catch (err) {
        log("auto-scan failed:", err && err.message);
      }
    })();
  }, initialDelay);

})();
