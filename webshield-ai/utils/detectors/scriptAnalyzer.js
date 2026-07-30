/* =============================================================================
 *  WebShield AI - Malicious JavaScript Detector
 *  -----------------------------------------------------------------------------
 *  Static-analysis-lite over every <script> tag on the page. We look for
 *  obfuscation indicators and dangerous primitives. External script bodies
 *  (including cross-origin ones) are fetched via the background service
 *  worker so attacker-hosted payloads aren't missed the way a page-context
 *  fetch() would miss them due to CORS.
 *
 *  Output:
 *    { score: 0..100, weight: 100, label: ..., findings: [...],
 *      stats: { total, suspicious } }
 * ============================================================================= */

(function () {
  "use strict";

  // Only primitives that meaningfully correlate with malicious behavior stay
  // in the flat rule list. localStorage/sessionStorage, btoa(), and bare
  // WebAssembly use are extremely common on legitimate sites (analytics,
  // feature flags, wasm image/video codecs) and were previously inflating
  // scores on completely benign pages, so they've been dropped.
  const RULES = [
    { name: "eval(",            regex: /\beval\s*\(/g,                     severity: 22 },
    { name: "new Function",     regex: /\bnew\s+Function\s*\(/g,           severity: 26 },
    { name: "Function(",        regex: /(?<![_a-zA-Z0-9])Function\s*\(/g, severity: 14 },
    { name: "atob(",            regex: /\batob\s*\(/g,                     severity: 10 },
    { name: "document.cookie",  regex: /document\.cookie/g,                 severity:  8 },
    { name: "navigator.plugins",regex: /navigator\.plugins/g,               severity: 10 },
    { name: "hardwareConcurrency", regex: /navigator\.hardwareConcurrency/g, severity:  8 }
  ];

  // Rule names that indicate the code can actually *execute* dynamic
  // content. Obfuscated-looking blobs (base64/hex/high-entropy) are only
  // meaningfully dangerous when paired with one of these — otherwise
  // they're just as likely to be a minified bundle, embedded font/image
  // data URI, or source map.
  const EXEC_RULE_NAMES = new Set(["eval(", "new Function", "Function(", "atob("]);

  /** Approximate Shannon-style entropy score for a string. */
  function entropy(s) {
    if (!s || s.length < 32) return 0;
    const freq = {};
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      freq[c] = (freq[c] || 0) + 1;
    }
    let h = 0;
    const len = s.length;
    for (const k in freq) {
      const p = freq[k] / len;
      h -= p * Math.log2(p);
    }
    return h; // typical English ~3.5, random base64 ~5.8
  }

  function looksLikeBase64(s) {
    if (!s || s.length < 100) return false;
    return /[A-Za-z0-9+/=]{100,}/.test(s);
  }

  function looksLikeHexBlob(s) {
    if (!s || s.length < 80) return false;
    return /\\x?[A-Fa-f0-9]{32,}/.test(s);
  }

  function hasObfuscationDensity(s) {
    if (!s || s.length < 200) return false;
    let sig = 0;
    sig += (s.match(/\\x[0-9A-Fa-f]{2}/g) || []).length;
    sig += (s.match(/_0x[0-9a-f]{4,}/g) || []).length;
    sig += (s.match(/\\u00[0-9a-f]{2}/g) || []).length;
    return sig > 25;
  }

  /** Inline-event-handler harvest: many XSS payloads are injected via
   *  `onerror="..."`, `onload="..."` etc. on injected nodes. We sample
   *  the first N nodes only to keep this fast on huge pages. */
  function harvestInlineHandlers() {
    const nodes = document.querySelectorAll("*");
    const max = Math.min(nodes.length, 1500);
    const out = [];
    for (let i = 0; i < max; i++) {
      const node = nodes[i];
      if (!node || !node.attributes) continue;
      for (const attr of node.attributes) {
        if (attr && attr.name && attr.name.toLowerCase().startsWith("on") &&
            typeof attr.value === "string" && attr.value.length > 4) {
          out.push(attr.value);
        }
      }
    }
    return out;
  }

  /** Fetch a remote script's source via the background service worker,
   *  which is not bound by the page's CORS policy (unlike a page-context
   *  fetch). This is what lets us actually see attacker-hosted payloads
   *  loaded from a third-party domain, not just same-origin bundles. */
  async function fetchExternal(url) {
    if (!url) return "";
    try {
      const resp = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: "FETCH_URL", url }, resolve);
      });
      return (resp && resp.ok && typeof resp.text === "string") ? resp.text : "";
    } catch (_) {
      return "";
    }
  }

  /** Main entry point. Async because we may fetch external script bodies. */
  async function run() {
    const scripts = Array.from(document.querySelectorAll("script"));
    const findings = [];
    let ruleScore = 0;
    let obfScore  = 0;
    let suspiciousCount = 0;

    const RULE_HIT_CAP = 65;
    const OBF_HIT_CAP  = 65;

    // -- Inline scripts ---------------------------------------------------
    scripts.forEach(s => {
      const code = s.src ? "" : (s.textContent || "");
      if (!code) return;
      analyseBlock(code, /* label */ "inline");
    });

    // -- Inline event handlers on DOM nodes -------------------------------
    const handlerCodes = harvestInlineHandlers();
    if (handlerCodes.length) {
      analyseBlock(handlerCodes.join("\n"), /* label */ "event-handler");
    }

    // -- External scripts (best-effort, fetch when CORS allows) ----------
    // We cap the number of fetches to avoid hammering the network.
    const externals = scripts.filter(s => s.src).slice(0, 10);
    for (const s of externals) {
      const code = await fetchExternal(s.src);
      if (code) analyseBlock(code, /* label */ "external");
    }

    // -------------------------------------------------------------------
    function analyseBlock(code, label) {
      if (!code || !code.length) return;

      let hitSomething = false;
      let hasExecPrimitive = false;

      for (const r of RULES) {
        r.regex.lastIndex = 0;
        const m = code.match(r.regex);
        if (m && m.length) {
          ruleScore += r.severity;
          hitSomething = true;
          if (EXEC_RULE_NAMES.has(r.name)) hasExecPrimitive = true;
          findings.push(`${r.name} ×${m.length} (${label})`);
        }
      }

      // Obfuscation-shaped content (long base64/hex, high entropy) is
      // extremely common in totally benign code (minified bundles, source
      // maps, embedded font/image data URIs), so alone it's weak evidence.
      // It's only strong evidence when the same block also contains a
      // primitive that executes dynamic content — "decode a blob, then
      // run it" is the actual attack shape, not obfuscation by itself.
      let localObf = 0;
      if (looksLikeBase64(code)) {
        localObf += 18;
        findings.push(`Long base64 string (${label})`);
      }
      if (looksLikeHexBlob(code)) {
        localObf += 15;
        findings.push(`Long hex blob (${label})`);
      }
      if (hasObfuscationDensity(code)) {
        localObf += 25;
        findings.push(`Obfuscation density (${label})`);
      }
      const WIN = 256, SAMPLES = 3;
      if (code.length > WIN) {
        for (let i = 0; i < SAMPLES; i++) {
          const start = Math.floor((code.length - WIN) * (i / SAMPLES));
          const slice = code.slice(start, start + WIN);
          if (entropy(slice) > 5.5) {
            localObf += 12;
            findings.push(`High-entropy block (${label})`);
            break;
          }
        }
      }

      if (localObf > 0) {
        hitSomething = true;
        // Full weight only when paired with an execution primitive in the
        // same block; otherwise heavily discounted (bundlers/data URIs).
        obfScore += hasExecPrimitive ? localObf : Math.round(localObf * 0.25);
      }

      if (hitSomething) suspiciousCount++;
    }

    ruleScore = Math.min(RULE_HIT_CAP, ruleScore);
    obfScore  = Math.min(OBF_HIT_CAP,  obfScore);
    const score = Math.min(100, ruleScore + obfScore);

    let label = "Safe";
    if (score >= 55) label = "Danger";
    else if (score >= 20) label = "Suspicious";

    return {
      score,
      weight: 100,
      label,
      findings: Array.from(new Set(findings)).slice(0, 8),
      stats: { total: scripts.length, suspicious: suspiciousCount }
    };
  }

  window.WebShieldDetectors = window.WebShieldDetectors || {};
  window.WebShieldDetectors.scriptAnalyzer = { run };
})();
