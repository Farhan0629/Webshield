/* =============================================================================
 *  WebShield AI - Drive-by Download Detector
 *  -----------------------------------------------------------------------------
 *  Drive-by downloads trigger a file save or open WITHOUT a clear user
 *  gesture. We look for the most common patterns:
 *
 *    - <a download="..."> elements that auto-trigger via JS click().
 *    - <a> / window.location assignments that point to .exe, .msi, .bat,
 *      .scr, .cmd, .ps1, .zip, .iso, etc.
 *    - Blob URLs created and clicked programmatically.
 *    - Hidden <iframe> whose src points to a downloadable file.
 *    - Content-Disposition: attachment responses (observed via fetch probes).
 *
 *  Like the cookie monitor, we use observation hooks that DO NOT change page
 *  behaviour — we only record what the page tries to do.
 *
 *  Output:
 *    { score: 0..100, weight: 100, label: ..., findings: [...] }
 * ============================================================================= */

(function () {
  "use strict";

  if (window.__webshield_download_monitor_installed__) return;
  window.__webshield_download_monitor_installed__ = true;

  const signals = {
    autoAnchorClicks: 0,
    blobAnchors:      0,
    scriptTriggeredDownloads: 0,
    hiddenIframes:    0,
    extensionDownloads: 0
  };

  const DANGEROUS_EXT = /\.(exe|msi|scr|bat|cmd|ps1|zip|iso|rar|7z|jar|dmg|pkg|apk|ipa)(\?|$|#)/i;

  /* -------------------- observation hooks -------------------------------- */

  // Anchor click observation.
  const origClick = HTMLAnchorElement.prototype.click;
  HTMLAnchorElement.prototype.click = function () {
    try {
      const href = this.href || "";
      const hasDownload = this.hasAttribute && this.hasAttribute("download");
      if (hasDownload) signals.autoAnchorClicks++;
      else if (DANGEROUS_EXT.test(href)) signals.extensionDownloads++;
      else if (/^blob:/.test(href)) signals.blobAnchors++;
    } catch (_) { /* ignore */ }
    return origClick.apply(this, arguments);
  };

  // Fetch probe — observe response Content-Disposition headers.
  const origFetch = window.fetch && window.fetch.bind(window);
  if (origFetch) {
    window.fetch = function (...args) {
      return origFetch(...args).then(res => {
        try {
          const disp = res.headers && res.headers.get && res.headers.get("content-disposition");
          if (disp && /attachment/i.test(disp)) signals.scriptTriggeredDownloads++;
        } catch (_) { /* ignore */ }
        return res;
      });
    };
  }

  /* -------------------------- run() ------------------------------------- */

  function run() {
    const findings = [];
    let score = 0;

    // 1) Inline <a download> elements that look auto-triggered (e.g. auto-click on load).
    const downloadAnchors = document.querySelectorAll('a[download]');
    let autoLikeAnchors = 0;
    downloadAnchors.forEach(a => {
      const s = window.getComputedStyle(a);
      if (s.visibility === "hidden" || s.display === "none" ||
          /display\s*:\s*none/.test(a.getAttribute("style") || "")) {
        autoLikeAnchors++;
      }
    });
    if (downloadAnchors.length > 0) {
      findings.push(`${downloadAnchors.length} <a download> element(s)`);
      score += Math.min(25, downloadAnchors.length * 6);
    }
    if (autoLikeAnchors > 0) {
      findings.push(`${autoLikeAnchors} hidden <a download> element(s)`);
      score += 25;
    }

    // 2) Blob/data-URL anchors in the DOM.
    const blobAnchors = document.querySelectorAll('a[href^="blob:"], a[href^="data:"]');
    if (blobAnchors.length > 0) {
      findings.push(`${blobAnchors.length} blob/data-URI anchor(s)`);
      score += Math.min(20, blobAnchors.length * 8);
    }

    // 3) Hidden iframes with executable source.
    const iframes = document.querySelectorAll("iframe");
    iframes.forEach(f => {
      const s = window.getComputedStyle(f);
      const invisible = s.visibility === "hidden" || s.display === "none" ||
                        parseFloat(s.opacity) === 0;
      const src = f.getAttribute("src") || "";
      if (invisible && DANGEROUS_EXT.test(src)) {
        signals.hiddenIframes++;
        findings.push(`Hidden iframe → executable URL`);
      }
    });

    // 4) Live observation counts accumulated since install.
    if (signals.autoAnchorClicks > 0) {
      findings.push(`${signals.autoAnchorClicks} programmatic anchor click(s)`);
      score += Math.min(30, signals.autoAnchorClicks * 15);
    }
    if (signals.blobAnchors > 0) {
      findings.push(`${signals.blobAnchors} blob-anchor click(s) observed`);
      score += Math.min(25, signals.blobAnchors * 8);
    }
    if (signals.scriptTriggeredDownloads > 0) {
      findings.push(`${signals.scriptTriggeredDownloads} attachment response(s)`);
      score += Math.min(40, signals.scriptTriggeredDownloads * 15);
    }
    if (signals.extensionDownloads > 0) {
      findings.push(`${signals.extensionDownloads} anchor(s) to executable extension`);
      score += Math.min(40, signals.extensionDownloads * 20);
    }
    if (signals.hiddenIframes > 0) {
      score += 30;
    }

    score = Math.max(0, Math.min(100, Math.round(score)));

    let label = "Safe";
    if (score >= 60) label = "Danger";
    else if (score >= 25) label = "Suspicious";

    return { score, weight: 100, label, findings };
  }

  window.WebShieldDetectors = window.WebShieldDetectors || {};
  window.WebShieldDetectors.downloadMonitor = { run, signals };
})();
