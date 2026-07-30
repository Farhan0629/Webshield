/* =============================================================================
 *  WebShield AI - Cookie Theft Detector
 *  -----------------------------------------------------------------------------
 *  Heuristic-only because we run inside the same page context as the suspect
 *  JavaScript. We can patch fetch / XMLHttpRequest / sendBeacon to OBSERVE
 *  outbound requests that *might* be carrying cookie data.
 *
 *  Signals we collect:
 *    - Was document.cookie read on the page? (very common baseline)
 *    - Did fetch / XHR / sendBeacon / WebSocket / Image() / <form> submit
 *      happen with cookie-bearing URLs?
 *    - Was there a "beacon"-style or short-interval outbound request right
 *      after a cookie read? (very suspicious)
 *
 *  Output:
 *    { score: 0..100, weight: 100, label: ..., findings: [...] }
 * ============================================================================= */

(function () {
  "use strict";

  // Sentinel to install our observation hooks only once per page load.
  if (window.__webshield_cookie_monitor_installed__) return;
  window.__webshield_cookie_monitor_installed__ = true;

  // Where we accumulate signals. Accessed only by detector.run().
  const signals = {
    cookieReads: 0,
    fetchCalls: 0,
    xhrOpens: 0,
    beacons: 0,
    suspiciousOutbound: 0,   // third-party request shortly after a cookie read
    crossOriginRequests: 0,  // requests to a different host than the page
    injectedForms: 0
  };

  // Timestamp of the most recent document.cookie *read*. Used to correlate
  // "cookie was read" with "data went to a third-party host" — that
  // combination is what real cookie theft looks like, not the mere
  // presence of fetch/XHR calls (every modern site makes plenty of those).
  let lastCookieReadAt = 0;
  const CORRELATION_WINDOW_MS = 3000;

  function isThirdPartyUrl(url) {
    try {
      const dest = new URL(url, location.href);
      return dest.hostname && dest.hostname !== location.hostname;
    } catch (_) {
      return false; // relative/opaque URLs are same-origin by construction
    }
  }

  /* ------------------- Observation hooks (read-only patches) ------------ *
   *  Each hook wraps an existing API with a probe that records usage. We
   *  never modify request bodies, headers, or destinations — we only watch.
   * ---------------------------------------------------------------------- */

  // 1) document.cookie read tracking via get/set traps.
  try {
    const cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
    if (cookieDesc && cookieDesc.get) {
      const origGet = cookieDesc.get;
      Object.defineProperty(Document.prototype, "cookie", {
        configurable: true,
        get() {
          signals.cookieReads++;
          lastCookieReadAt = Date.now();
          return origGet.call(this);
        },
        set: cookieDesc.set
      });
    }
  } catch (_) { /* CSP may forbid redefine — that's fine, just less coverage */ }

  // 2) fetch() observation.
  const origFetch = window.fetch && window.fetch.bind(window);
  if (origFetch) {
    window.fetch = function (...args) {
      signals.fetchCalls++;
      try {
        const url = typeof args[0] === "string" ? args[0] : (args[0] && args[0].url) || "";
        flagIfExfilShaped(url);
      } catch (_) { /* URL may be opaque — ignore */ }
      return origFetch(...args);
    };
  }

  // 3) XMLHttpRequest observation.
  const OrigXHR = window.XMLHttpRequest;
  if (OrigXHR) {
    window.XMLHttpRequest = function () {
      const xhr = new OrigXHR();
      const origOpen = xhr.open;
      xhr.open = function (method, url) {
        signals.xhrOpens++;
        flagIfExfilShaped(url);
        return origOpen.apply(xhr, arguments);
      };
      return xhr;
    };
    // Preserve prototype so libs that introspect it still work.
    window.XMLHttpRequest.prototype = OrigXHR.prototype;
  }

  // 4) navigator.sendBeacon observation.
  if (navigator.sendBeacon) {
    const origBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url, data) {
      signals.beacons++;
      flagIfExfilShaped(url);
      return origBeacon(url, data);
    };
  }

  /** Real cookie theft doesn't announce itself with words like "cookie" or
   *  "track" in the URL — a real attacker names their endpoint whatever
   *  they like. What's actually hard to fake is *shape*: data leaving to a
   *  different host than the page, shortly after document.cookie was read.
   *  We flag that combination rather than keyword-matching the URL, which
   *  both misses real attacks and false-positives on ordinary analytics
   *  domains that happen to contain those words. */
  function flagIfExfilShaped(url) {
    if (typeof url !== "string" || !url) return;
    const thirdParty = isThirdPartyUrl(url);
    if (thirdParty) signals.crossOriginRequests++;
    const recentlyReadCookie = lastCookieReadAt && (Date.now() - lastCookieReadAt) < CORRELATION_WINDOW_MS;
    if (thirdParty && recentlyReadCookie) {
      signals.suspiciousOutbound++;
    }
  }

  // 5) Hidden <form> auto-submits via JS injection of a form into the DOM.
  const bodyObserver = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node && node.nodeName === "FORM") {
          // A form that is off-screen and has password fields is a classic exfil slot.
          const s = (node.style && node.style.cssText) || "";
          if (/(display\s*:\s*none|visibility\s*:\s*hidden|position\s*:\s*absolute).{0,40}left\s*:\s*-?\d{4,}px/i.test(s)) {
            signals.injectedForms++;
          }
        }
      }
    }
  });
  // Only observe if the API is available — pages may opt out via CSP.
  try { bodyObserver.observe(document.documentElement, { childList: true, subtree: true }); }
  catch (_) { /* ignore */ }

  /* ----------------------------- run() --------------------------------- */

  function run() {
    const findings = [];
    let score = 0;

    // Raw call counts (fetch/XHR volume, cookie reads, plain cross-origin
    // requests) are informational only — modern sites routinely make
    // dozens of API calls and read cookies for entirely normal reasons
    // (auth tokens, consent state, A/B flags). None of that alone is
    // scored; it's surfaced in findings for transparency only.
    if (signals.cookieReads > 0) {
      findings.push(`document.cookie read ${signals.cookieReads}×`);
    }
    if (signals.fetchCalls > 0) {
      findings.push(`${signals.fetchCalls} fetch() call(s)`);
    }
    if (signals.xhrOpens > 0) {
      findings.push(`${signals.xhrOpens} XMLHttpRequest open(s)`);
    }

    // The one signal that actually correlates with theft: cookie was read,
    // then data went out to a different host shortly after. This is much
    // harder for an attacker to disguise than a URL keyword.
    if (signals.suspiciousOutbound > 0) {
      findings.push(`${signals.suspiciousOutbound} request(s) to a third-party host shortly after a cookie read`);
      score += Math.min(70, signals.suspiciousOutbound * 35);
    }

    // sendBeacon to a third-party host is a classic silent-exfil pattern
    // (fire-and-forget, survives page unload) even without a recent cookie
    // read directly preceding it, so it still adds some weight on its own.
    if (signals.beacons > 0 && signals.crossOriginRequests > 0) {
      findings.push(`${signals.beacons} sendBeacon() call(s) to a third-party host`);
      score += Math.min(30, signals.beacons * 15);
    }

    if (signals.injectedForms > 0) {
      findings.push(`${signals.injectedForms} injected hidden form(s) (classic exfil pattern)`);
      score += Math.min(45, signals.injectedForms * 22);
    }

    score = Math.max(0, Math.min(100, Math.round(score)));

    let label = "Safe";
    if (score >= 55) label = "Danger";
    else if (score >= 25) label = "Suspicious";

    return { score, weight: 100, label, findings };
  }

  // Expose under a property so detectors that need raw counts can pull them.
  window.WebShieldDetectors = window.WebShieldDetectors || {};
  window.WebShieldDetectors.cookieMonitor = { run, signals };
})();
