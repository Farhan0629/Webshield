/* =============================================================================
 *  WebShield AI - Risk Engine (simplified)
 *  -----------------------------------------------------------------------------
 *  Generates plain-English recommendations based on per-detector threat labels.
 *  The aggregate score system has been removed in favor of a simple
 *  "X of Y detectors flagged" counter in the popup.
 * ============================================================================= */

(function () {
  "use strict";

  /**
   * Convert a number 0-100 into the matching threat band label.
   * @param {number} score
   */
  function classify(score) {
    if (score <= 20) return "Safe";
    if (score <= 40) return "Low";
    if (score <= 60) return "Medium";
    if (score <= 80) return "High";
    return "Critical";
  }

  /**
   * Build recommendation strings from the detected threat map.
   * @param {Object<string,"Safe"|"Suspicious"|"Danger">} threats
   */
  function recommend(threats) {
    const tips = [];

    if (threats["DOM XSS"] === "Danger") {
      tips.push("Close this page — it uses dangerous DOM sinks (eval, innerHTML).");
    } else if (threats["DOM XSS"] === "Suspicious") {
      tips.push("This page uses dynamic DOM construction. Be careful entering credentials.");
    }

    if (threats["Clickjacking"] === "Danger") {
      tips.push("Possible clickjacking overlay detected. Do not click links on this page.");
    } else if (threats["Clickjacking"] === "Suspicious") {
      tips.push("Hidden iframes were found. Verify the URL is the one you intended to visit.");
    }

    if (threats["Malicious JS"] === "Danger") {
      tips.push("Highly obfuscated JavaScript detected. Avoid interacting with this page.");
    } else if (threats["Malicious JS"] === "Suspicious") {
      tips.push("Unusual JavaScript patterns detected (eval/atob/encoded strings).");
    }

    if (threats["Cookie Theft"] === "Danger") {
      tips.push("Cookies may be exfiltrated to an external endpoint. Leave immediately.");
    } else if (threats["Cookie Theft"] === "Suspicious") {
      tips.push("Possible outbound transmission of cookie data — close other tabs first.");
    }

    if (threats["Crypto Miner"] === "Danger") {
      tips.push("Cryptomining activity detected. Close this tab to free your CPU.");
    } else if (threats["Crypto Miner"] === "Suspicious") {
      tips.push("Mining-like CPU loops detected. Watch your battery and CPU usage.");
    }

    if (threats["Drive-by Download"] === "Danger") {
      tips.push("This page may have triggered an automatic download. Do not run any file.");
    } else if (threats["Drive-by Download"] === "Suspicious") {
      tips.push("Suspicious download mechanism in use. Decline any download prompts.");
    }

    if (threats["Permission Snooping"] === "Danger") {
      tips.push("This page is accessing your camera, microphone, or location. Revoke permissions and close this site now.");
    } else if (threats["Permission Snooping"] === "Suspicious") {
      tips.push("This page is requesting sensitive permissions (camera / mic / location). Decline the prompts and leave.");
    }

    if (tips.length === 0) {
      tips.push("This page appears safe.");
    } else {
      tips.push("Leave this website immediately if you did not expect to land here.");
    }
    return tips;
  }

  // Expose on window so content.js can reach us after content_scripts load order.
  window.WebShieldRiskEngine = { classify, recommend };
})();
