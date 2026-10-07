/* =============================================================================
 *  WebShield AI - Advanced Risk Engine (SOC Analyst Confidence Model)
 *  -----------------------------------------------------------------------------
 *  Redesigned overall risk scoring engine (0-100) based on confidence analysis.
 *  Prevents false positives on modern Single Page Applications (YouTube, Gmail,
 *  Facebook, Chess.com) by categorizing detectors into Weak Heuristics and
 *  Strong Security Indicators, applying base risk matrices, multi-vector
 *  correlation bonuses, high-threat combination synergies, and critical floors.
 * ============================================================================= */

(function () {
  "use strict";

  // ---------------------------------------------------------------------------
  // CONFIGURATION CONSTANTS (Modular & Easy to Tune)
  // ---------------------------------------------------------------------------
  const CONFIG = {
    // 1. Detector Categories
    CATEGORIES: {
      WEAK: ["DOM XSS", "Malicious JS"],
      STRONG: [
        "Cookie Theft",
        "Permission Snooping",
        "Drive-by Download",
        "Clickjacking",
        "Crypto Miner",
        "Safe Browsing"
      ]
    },

    // 2. Minimum raw detector score required to be considered "Triggered"
    // Heuristic detectors (like DOM XSS) produce noise at low scores.
    TRIGGER_THRESHOLDS: {
      "DOM XSS": 40,             // Weak heuristic threshold
      "Malicious JS": 40,        // Weak heuristic threshold
      "Clickjacking": 25,        // Strong indicator threshold
      "Cookie Theft": 30,        // Strong indicator threshold
      "Crypto Miner": 30,        // Strong indicator threshold
      "Drive-by Download": 30,   // Strong indicator threshold
      "Permission Snooping": 25, // Strong indicator threshold
      "Safe Browsing": 50        // Strong indicator threshold
    },

    // 3. Base Risk Calculation Matrix
    // Weak-only detectors contribute very low risk to prevent false positives on modern SPAs.
    BASE_RISK: {
      WEAK_ONLY: { 0: 0, 1: 5, 2: 12 },
      STRONG_BASE: { 1: 25, 2: 45, 3: 65, 4: 80 },
      WEAK_WITH_STRONG_BOOST: 5
    },

    // 4. Correlation Bonuses (Multi-Detector Agreement)
    // The more independent security indicators agree, the higher the confidence.
    CORRELATION_BONUSES: {
      3: 15,  // 3 triggered detectors -> +15
      4: 30,  // 4 triggered detectors -> +30
      5: 45,  // 5 triggered detectors -> +45
      6: 60   // 6+ triggered detectors -> +60
    },

    // 5. Combination Bonuses (Synergistic Attack Vectors)
    // Meaningful security pairs/triplets that represent concrete malicious behavior.
    // NOTE: DOM XSS + Malicious JS alone is explicitly EXCLUDED (0 bonus).
    COMBINATION_BONUSES: [
      {
        id: "xss_cookie",
        detectors: ["DOM XSS", "Cookie Theft"],
        bonus: 25,
        reason: "DOM XSS + Cookie Theft (Session Hijacking Pattern)"
      },
      {
        id: "cookie_perm",
        detectors: ["Cookie Theft", "Permission Snooping"],
        bonus: 25,
        reason: "Cookie Theft + Permission Snooping (Data Harvesting Pattern)"
      },
      {
        id: "script_download",
        detectors: ["Malicious JS", "Drive-by Download"],
        bonus: 20,
        reason: "Malicious JS + Drive-by Download (Malware Dropper Pattern)"
      },
      {
        id: "clickjack_download",
        detectors: ["Clickjacking", "Drive-by Download"],
        bonus: 20,
        reason: "Clickjacking + Drive-by Download (Tricked Download Trap)"
      },
      {
        id: "sb_synergy",
        detectors: ["Safe Browsing"],
        requiresAnyOther: true,
        bonus: 35,
        reason: "Google Safe Browsing + Local Threat Correlation"
      }
    ],

    // 6. Critical Event Overrides (Guaranteed Minimum Score Floors)
    CRITICAL_OVERRIDES: [
      {
        detector: "Safe Browsing",
        minRawScore: 50,
        floorScore: 100,
        reason: "Confirmed malicious domain reported by Google Safe Browsing"
      },
      {
        detector: "Crypto Miner",
        minRawScore: 60,
        floorScore: 80,
        reason: "Active Cryptomining Web Worker running on page"
      },
      {
        detector: "Cookie Theft",
        minRawScore: 50,
        floorScore: 75,
        reason: "Confirmed Cookie Exfiltration to third-party host"
      },
      {
        detector: "Drive-by Download",
        minRawScore: 50,
        floorScore: 70,
        reason: "Executable file drive-by download detected"
      }
    ],

    // 7. Rating Thresholds & Tones
    RATING_THRESHOLDS: [
      { max: 20, rating: "Safe", class: "rating-safe", tone: "safe" },
      { max: 40, rating: "Low Risk", class: "rating-low", tone: "warning" },
      { max: 60, rating: "Suspicious", class: "rating-suspicious", tone: "warning" },
      { max: 80, rating: "High Risk", class: "rating-high", tone: "danger" },
      { max: 100, rating: "Critical", class: "rating-critical", tone: "critical" }
    ]
  };

  /**
   * Main Risk Engine Evaluation Function
   * Computes confidence-based overall risk score (0-100) and transparent explanation.
   * @param {Array<{name: string, score: number, label: string, hitCount?: number}>} detectorResults
   * @returns {Object} Full Risk Evaluation
   */
  function evaluateOverallRisk(detectorResults) {
    if (!Array.isArray(detectorResults) || detectorResults.length === 0) {
      return {
        score: 0,
        rating: "Safe",
        tone: "safe",
        ratingClass: "rating-safe",
        reasons: ["No active threats or diagnostic data found."],
        highestContributor: "None",
        triggeredDetectors: [],
        baseRisk: 0,
        correlationBonus: 0,
        combinationBonusTotal: 0
      };
    }

    // Step 1: Filter Triggered Detectors
    const triggeredMap = {};
    const triggeredList = [];
    let weakCount = 0;
    let strongCount = 0;

    let highestScore = -1;
    let highestContributor = "None";

    detectorResults.forEach(item => {
      const name = item.name;
      const score = typeof item.score === "number" ? item.score : 0;
      const threshold = CONFIG.TRIGGER_THRESHOLDS[name] || 30;

      if (score > highestScore && score > 0) {
        highestScore = score;
        highestContributor = name;
      }

      if (score >= threshold) {
        const isWeak = CONFIG.CATEGORIES.WEAK.includes(name);
        const isStrong = CONFIG.CATEGORIES.STRONG.includes(name);

        triggeredMap[name] = { name, score, isWeak, isStrong };
        triggeredList.push(name);

        if (isWeak) weakCount++;
        if (isStrong) strongCount++;
      }
    });

    const reasons = [];

    // Step 2: Compute Base Risk
    let baseRisk = 0;
    if (strongCount === 0) {
      baseRisk = CONFIG.BASE_RISK.WEAK_ONLY[weakCount] || (weakCount >= 2 ? 12 : 0);
    } else {
      const strongBase = CONFIG.BASE_RISK.STRONG_BASE[strongCount] || 80;
      const weakBoost = weakCount * CONFIG.BASE_RISK.WEAK_WITH_STRONG_BOOST;
      baseRisk = strongBase + weakBoost;
    }

    // Document triggered detectors
    if (triggeredList.length === 0) {
      reasons.push("All security indicators are within safe parameters.");
    } else {
      triggeredList.forEach(name => {
        const isWeak = CONFIG.CATEGORIES.WEAK.includes(name);
        const categoryLabel = isWeak ? "Weak Heuristic" : "Strong Indicator";
        reasons.push(`${name} detected (${categoryLabel})`);
      });
    }

    // Step 3: Correlation Bonuses
    let correlationBonus = 0;
    const totalCount = triggeredList.length;
    if (totalCount >= 6) correlationBonus = CONFIG.CORRELATION_BONUSES[6];
    else if (totalCount >= 5) correlationBonus = CONFIG.CORRELATION_BONUSES[5];
    else if (totalCount >= 4) correlationBonus = CONFIG.CORRELATION_BONUSES[4];
    else if (totalCount >= 3) correlationBonus = CONFIG.CORRELATION_BONUSES[3];

    if (correlationBonus > 0) {
      reasons.push(`Correlation bonus applied for ${totalCount} independent detectors (+${correlationBonus})`);
    }

    // Step 4: Combination Bonuses
    let combinationBonusTotal = 0;
    CONFIG.COMBINATION_BONUSES.forEach(combo => {
      let matched = false;
      if (combo.requiresAnyOther) {
        const hasMain = combo.detectors.every(d => !!triggeredMap[d]);
        const hasOthers = triggeredList.some(d => !combo.detectors.includes(d));
        matched = hasMain && hasOthers;
      } else {
        matched = combo.detectors.every(d => !!triggeredMap[d]);
      }

      if (matched) {
        combinationBonusTotal += combo.bonus;
        reasons.push(`Synergy bonus: ${combo.reason} (+${combo.bonus})`);
      }
    });

    let computedScore = baseRisk + correlationBonus + combinationBonusTotal;

    // Step 5: Critical Event Overrides
    let appliedFloor = 0;
    CONFIG.CRITICAL_OVERRIDES.forEach(override => {
      const item = detectorResults.find(d => d.name === override.detector);
      if (item && item.score >= override.minRawScore) {
        if (override.floorScore > appliedFloor) {
          appliedFloor = override.floorScore;
          reasons.push(`Critical Floor Override: ${override.reason} (Floor: ${override.floorScore})`);
        }
      }
    });

    let finalScore = Math.max(computedScore, appliedFloor);
    finalScore = Math.max(0, Math.min(100, Math.round(finalScore)));

    // Step 6: Rating Threshold Mapping
    let ratingObj = CONFIG.RATING_THRESHOLDS[0];
    for (const r of CONFIG.RATING_THRESHOLDS) {
      if (finalScore <= r.max) {
        ratingObj = r;
        break;
      }
    }

    return {
      score: finalScore,
      rating: ratingObj.rating,
      tone: ratingObj.tone,
      ratingClass: ratingObj.class,
      baseRisk,
      correlationBonus,
      combinationBonusTotal,
      reasons,
      highestContributor: highestContributor !== "None" ? highestContributor : "None",
      triggeredDetectors: triggeredList
    };
  }

  /** Convert score 0-100 into standard rating string */
  function classify(score) {
    if (score <= 20) return "Safe";
    if (score <= 40) return "Low Risk";
    if (score <= 60) return "Suspicious";
    if (score <= 80) return "High Risk";
    return "Critical";
  }

  /** Build recommendations list from threats map */
  function recommend(threats) {
    const tips = [];

    if (threats["DOM XSS"] === "Danger") {
      tips.push("This page uses dynamic DOM construction (eval, innerHTML). Exercise caution.");
    }
    if (threats["Clickjacking"] === "Danger") {
      tips.push("Possible clickjacking overlay detected. Do not click unverified links on this page.");
    }
    if (threats["Malicious JS"] === "Danger") {
      tips.push("Highly obfuscated JavaScript detected. Avoid interacting with this page.");
    }
    if (threats["Cookie Theft"] === "Danger" || threats["Cookie Theft"] === "Suspicious") {
      tips.push("Possible cookie exfiltration detected. Close other sensitive tabs immediately.");
    }
    if (threats["Crypto Miner"] === "Danger" || threats["Crypto Miner"] === "Suspicious") {
      tips.push("Cryptomining Web Worker activity detected. Close this tab to free CPU resources.");
    }
    if (threats["Drive-by Download"] === "Danger" || threats["Drive-by Download"] === "Suspicious") {
      tips.push("Automatic or hidden executable download detected. Do not run downloaded files.");
    }
    if (threats["Permission Snooping"] === "Danger" || threats["Permission Snooping"] === "Suspicious") {
      tips.push("This site is probing sensitive sensors (location, mic, camera, clipboard). Revoke unnecessary permissions.");
    }
    if (threats["Safe Browsing"] === "Danger") {
      tips.push("FLAGGED BY GOOGLE SAFE BROWSING: Leave this domain immediately!");
    }

    if (tips.length === 0) {
      tips.push("This page appears safe based on local and reputation analysis.");
    }
    return tips;
  }

  /* Export to globalThis so it works in both content scripts (window)
     and Manifest V3 service workers (self). */
  var _global = typeof globalThis !== "undefined" ? globalThis
              : typeof self !== "undefined" ? self
              : typeof window !== "undefined" ? window : {};
  _global.WebShieldRiskEngine = {
    CONFIG,
    evaluateOverallRisk,
    classify,
    recommend
  };
})();
