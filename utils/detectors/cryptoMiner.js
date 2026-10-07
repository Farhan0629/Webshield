/* =============================================================================
 *  WebShield AI - Cryptominer Detector
 *  -----------------------------------------------------------------------------
 *  Browser-based cryptojacking usually shows up as one of:
 *    - Inlined miner libraries (CoinHive family: coinhive, crypto-loot,
 *      deepminer, jsecoin, authedmine, etc.)
 *    - Mention of CryptoNight / RandomX / SHA-256 hashing primitives in code
 *    - Heavy CPU loops: setInterval with very short delays, while loops
 *      with no break, or Web Workers holding the CPU.
 *    - Web Workers spun up from inline blob/data URIs.
 *    - WASM modules used for hashing.
 *
 *  Detector: purely static / behavioural observation. No CPU profiling.
 *
 *  Output:
 *    { score: 0..100, weight: 100, label: ..., findings: [...] }
 * ============================================================================= */

(function () {
  "use strict";

  // Known in-browser miner patterns — substring search of all script sources.
  const MINER_KEYWORDS = [
    "coinhive", "cryptoloot", "crypto-loot", "coin-hive", "jsecoin",
    "deepminer", "authedmine", "webminerpool", "coin-hive", "minero",
    "cryptonight", "cryptonight.js", "monero-miner", "wasmminer",
    "webmine", "webmine.cz", "minemytraffic"
  ];

  // Hash algorithms commonly implemented by in-browser miners.
  const HASH_KEYWORDS = ["cryptonight", "randomx", "argon2", "yespower", "kawpow"];

  // Inspect every script tag and web worker setup call.
  function harvestCode() {
    const code = [];
    document.querySelectorAll("script").forEach(s => {
      if (!s.src) code.push(s.textContent || "");
    });

    // Also scan for `new Worker(blob:...)` / `new Worker(data:...)`.
    // We collect script sources for inline creation payloads from the surrounding
    // text, which covers the typical "blob worker with mining loop" pattern.
    document.querySelectorAll("script").forEach(s => {
      const src = s.src || s.getAttribute("src") || "";
      if (/^blob:|^data:/.test(src)) code.push(s.outerHTML);
    });
    return code.join("\n");
  }

  function run() {
    const findings = [];
    let score = 0;

    const combined = harvestCode();
    const lower = combined.toLowerCase();

    // 1) Known miner library keywords.
    let minerHits = 0;
    for (const kw of MINER_KEYWORDS) {
      const m = lower.split(kw).length - 1;
      if (m > 0) {
        minerHits += m;
        findings.push(`Known miner keyword: ${kw} (${m}×)`);
      }
    }
    if (minerHits > 0) score += Math.min(60, minerHits * 25);

    // 2) Hashing-algorithm keywords (strong signal but not definitive on their own).
    let hashHits = 0;
    for (const kw of HASH_KEYWORDS) {
      const m = lower.split(kw).length - 1;
      if (m > 0) {
        hashHits += m;
        findings.push(`Hash algo keyword: ${kw} (${m}×)`);
      }
    }
    if (hashHits > 0) score += Math.min(30, hashHits * 12);

    // 3) WebAssembly instance combined with hashing primes a likely miner.
    if (/WebAssembly\.instantiate/.test(combined) && hashHits > 0) {
      findings.push("WebAssembly + hash algo combination");
      score += 20;
    }

    // 4) Aggressive setInterval usage — many miners tick every ~50ms.
    const shortIntervals = (combined.match(/setInterval\s*\(\s*[^,]+,\s*[0-9]{1,3}\s*\)/g) || []).length;
    if (shortIntervals >= 3) {
      findings.push(`${shortIntervals} short-period setInterval tick(s)`);
      score += Math.min(25, shortIntervals * 6);
    }

    // 5) Spin loops — endless while/for without break/return inside the body.
    let whileLoops = (combined.match(/while\s*\([^)]*(?:true|1|!0)[^)]*\)\s*\{/g) || []).length;
    if (whileLoops >= 2) {
      findings.push(`${whileLoops} tight while-true loop(s)`);
      score += Math.min(20, whileLoops * 8);
    }

    // 6) Worker creation from blob/data URIs.
    const workerBlobs = (combined.match(/new\s+Worker\s*\(\s*["'](?:blob|data):/g) || []).length;
    if (workerBlobs > 0) {
      findings.push(`${workerBlobs} blob/data-URI Worker(s)`);
      score += Math.min(20, workerBlobs * 10);
    }

    score = Math.max(0, Math.min(100, Math.round(score)));

    let label = "Safe";
    if (score >= 55) label = "Danger";
    else if (score >= 20) label = "Suspicious";

    return { score, weight: 100, label, findings };
  }

  window.WebShieldDetectors = window.WebShieldDetectors || {};
  window.WebShieldDetectors.cryptoMiner = { run };
})();
