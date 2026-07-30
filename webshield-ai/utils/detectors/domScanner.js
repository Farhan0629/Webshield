/* =============================================================================
 *  WebShield AI - DOM XSS Detector
 *  -----------------------------------------------------------------------------
 *  Looks for code patterns and DOM constructions commonly used as part of a
 *  DOM-based XSS attack chain. These are warning signs — not a definitive
 *  determination that an attack is happening.
 *
 *  Scans both inline scripts and external script bodies (fetched via the
 *  background service worker, which isn't subject to the page's CORS
 *  policy) so third-party/attacker-hosted code is covered too.
 *
 *  What we look for:
 *    - Dynamic script execution sinks: eval(), new Function(), setTimeout("…"),
 *      setInterval("…").
 *    - Unsafe DOM injection sinks: innerHTML, outerHTML, insertAdjacentHTML(),
 *      document.write(), document.writeln().
 *    - The presence of suspicious user-controlled input sources:
 *        location.hash, location.search, document.referrer, postMessage.
 *    - Active workflows where a sink receives what looks like URL-derived data.
 *
 *  Output:
 *    { score: 0..100, weight: 100, label: "Safe"|"Suspicious"|"Danger",
 *      findings: [...] }
 * ============================================================================= */

(function () {
  "use strict";

  // Each sink is [name, severity-add]. severity-add contributes to the score
  // when this sink is detected anywhere on the page.
  const SINKS = [
    { regex: /\beval\s*\(/g,                              name: "eval()",                 severity: 25 },
    { regex: /\bnew\s+Function\s*\(/g,                    name: "new Function()",         severity: 30 },
    { regex: /\bsetTimeout\s*\(\s*["'`]/g,               name: "setTimeout(string)",     severity: 20 },
    { regex: /\bsetInterval\s*\(\s*["'`]/g,              name: "setInterval(string)",    severity: 20 },
    { regex: /\.innerHTML\s*=/g,                          name: "innerHTML =",            severity: 15 },
    { regex: /\.outerHTML\s*=/g,                          name: "outerHTML =",            severity: 20 },
    { regex: /\.insertAdjacentHTML\s*\(/g,                name: "insertAdjacentHTML()",   severity: 15 },
    { regex: /document\.write(ln)?\s*\(/g,                name: "document.write()",       severity: 25 }
  ];

  // Source indicators — if we see these AND a sink, the report gets Danger.
  const SOURCES = [
    { regex: /location\.hash/g,    name: "location.hash" },
    { regex: /location\.search/g,  name: "location.search" },
    { regex: /document\.referrer/g,name: "document.referrer" },
    { regex: /window\.name/g,      name: "window.name" },
    { regex: /\bpostMessage\b/g,   name: "postMessage" }
  ];

  /** Fetch a remote script's source via the background service worker,
   *  which bypasses the page's CORS restriction (unlike a page-context
   *  fetch), so third-party/attacker-hosted scripts get scanned too. */
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

  /**
   * Walk all <script> tags and inline event handlers, tallying suspicious
   * patterns. We never execute the script, we only read its source.
   * Async because external script bodies are fetched via the background
   * relay (previously external scripts were skipped entirely, which meant
   * a page's actual attack code — usually loaded from a third-party
   * domain — was invisible to this detector).
   */
  async function harvestScriptSources() {
    const sources = [];
    const externalUrls = [];

    // 1) <script> tags: inline text read directly, external src queued.
    document.querySelectorAll("script").forEach(s => {
      if (!s.src && s.textContent) sources.push(s.textContent);
      else if (s.src) externalUrls.push(s.src);
    });

    // Cap fetches to avoid hammering the network on script-heavy pages.
    for (const url of externalUrls.slice(0, 10)) {
      const code = await fetchExternal(url);
      if (code) sources.push(code);
    }

    // 2) Inline event handlers on the elements of the document.
    // We sample the first 1000 nodes to keep this fast on huge pages.
    const nodes = document.querySelectorAll("*");
    const max = Math.min(nodes.length, 1000);
    for (let i = 0; i < max; i++) {
      const node = nodes[i];
      if (node.attributes) {
        for (const attr of node.attributes) {
          if (attr && typeof attr.value === "string" &&
              attr.name && attr.name.toLowerCase().startsWith("on") &&
              attr.value.length > 4) {
            sources.push(attr.value);
          }
        }
      }
    }
    return sources;
  }

  /**
   * Main entry point. Returns a detector result in the standard shape.
   * @returns {{score:number, weight:number, label:string, findings:Array}}
   */
  async function run() {
    const findings = [];
    let rawScore = 0;

    const sourceTexts = await harvestScriptSources();
    const combined = sourceTexts.join("\n");

    // Count sinks found anywhere on the page.
    let sinksHit = [];
    for (const sink of SINKS) {
      sink.regex.lastIndex = 0;
      const matches = combined.match(sink.regex);
      if (matches && matches.length) {
        sinksHit.push({ name: sink.name, count: matches.length });
        // Cap each sink's contribution to avoid one noisy site skewing the result.
        rawScore += Math.min(sink.severity, sink.severity * Math.log2(matches.length + 1));
        findings.push(`${sink.name} used ${matches.length}×`);
      }
    }

    // Detect sources of untrusted input too.
    let sourcesHit = [];
    for (const src of SOURCES) {
      src.regex.lastIndex = 0;
      const m = combined.match(src.regex);
      if (m && m.length) sourcesHit.push(src.name);
    }

    // Heuristic: a sink AND an untrusted-input source co-occurring is dangerous.
    if (sinksHit.length > 0 && sourcesHit.length > 0) {
      rawScore += 25;
      findings.push("Untrusted input source combined with DOM sink");
    }

    // Clamp the raw score to 0..100.
    const score = Math.max(0, Math.min(100, Math.round(rawScore)));

    let label = "Safe";
    if (score >= 50) label = "Danger";
    else if (score >= 20) label = "Suspicious";

    return { score, weight: 100, label, findings };
  }

  // Expose detector under a stable global namespace.
  window.WebShieldDetectors = window.WebShieldDetectors || {};
  window.WebShieldDetectors.domScanner = { run };
})();
