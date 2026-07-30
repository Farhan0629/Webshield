/* =============================================================================
 *  WebShield AI - Clickjacking Detector
 *  -----------------------------------------------------------------------------
 *  Clickjacking tricks the user into clicking something that isn't what it
 *  appears to be. The classic recipe is a transparent or fullscreen iframe
 *  layered over a fake UI. We look for visual / z-order tricks in the DOM
 *  that make UI elements effectively invisible or capture all clicks.
 *
 *  What we look for:
 *    - Iframes with opacity:0, visibility:hidden, display:none, very small
 *      dimensions, or position:fixed at 100% width/height (fullscreen).
 *    - Elements with very high z-index AND pointer-events handling that
 *      could absorb clicks.
 *    - Buttons with zero opacity, off-screen positioning, or hidden via clip.
 *
 *  Output:
 *    { score: 0..100, weight: 100, label: "Safe"|"Suspicious"|"Danger",
 *      findings: [...] }
 * ============================================================================= */

(function () {
  "use strict";

  /** Read a numeric value from a CSSStyleDeclaration, returning NaN if absent. */
  function num(style, prop) {
    if (!style) return NaN;
    const v = style.getPropertyValue(prop);
    return parseFloat(v);
  }

  /** Read a string value from a CSSStyleDeclaration, returning "" if absent. */
  function str(style, prop) {
    if (!style) return "";
    return style.getPropertyValue(prop) || "";
  }

  /** True if the computed style of `el` makes it effectively invisible. */
  function isInvisible(el) {
    const s = window.getComputedStyle(el);
    if (!s) return false;
    if (s.visibility === "hidden") return true;
    if (s.display === "none") return true;
    if (num(s, "opacity") === 0) return true;
    // CSS clip / clip-path that fully clips it out.
    const clip = str(s, "clip") || str(s, "clip-path");
    if (clip && /inset\(100%|rect\(0/.test(clip)) return true;
    return false;
  }

  /** True if the iframe covers most of the viewport — fullscreen tricks. */
  function isFullscreenCover(el) {
    const r = el.getBoundingClientRect();
    const vw = Math.max(document.documentElement.clientWidth, window.innerWidth || 0);
    const vh = Math.max(document.documentElement.clientHeight, window.innerHeight || 0);
    return r.width >= vw * 0.9 && r.height >= vh * 0.9;
  }

  /** True if the iframe is so tiny it can effectively sit on top of a button. */
  function isTiny(el) {
    const r = el.getBoundingClientRect();
    return r.width <= 5 || r.height <= 5 || (r.width * r.height < 50);
  }

  /**
   * Walk all elements once, accumulating signals. We avoid premature work.
   */
  function run() {
    const findings = [];
    let score = 0;

    const iframes = Array.from(document.querySelectorAll("iframe"));
    let dangerousIframes = 0;
    let tinyIframes = 0;

    iframes.forEach(f => {
      const s = window.getComputedStyle(f);
      const invisible = isInvisible(f);
      const fullscreen = isFullscreenCover(f);
      const tiny = isTiny(f);
      const opacity = num(s, "opacity");
      const zIndex = num(s, "z-index");

      if ((invisible || opacity === 0) && !tiny) {
        // Invisible full-page iframe = textbook clickjacking.
        dangerousIframes++;
        findings.push(`Invisible iframe (opacity=${opacity}, z-index=${zIndex})`);
        score += 35;
      } else if (tiny && !invisible) {
        tinyIframes++;
        score += 20;
      } else if (fullscreen && !invisible) {
        // Fullscreen visible iframe on top of unknown UI.
        if (!isNaN(zIndex) && zIndex > 100) {
          dangerousIframes++;
          findings.push("Fullscreen iframe with elevated z-index");
          score += 30;
        }
      }
    });

    /* ------------------------------------------------------ *
     *  Overlay traps: a fixed/absolute element that lies
     *  above the entire viewport and silently absorbs clicks.
     * ------------------------------------------------------ */
    const all = document.querySelectorAll("body *");
    const max = Math.min(all.length, 1500);
    for (let i = 0; i < max; i++) {
      const el = all[i];
      const s = window.getComputedStyle(el);
      const pos = str(s, "position");
      const pe  = str(s, "pointer-events");
      const z   = num(s, "z-index");
      const opacity = num(s, "opacity");
      const rect = el.getBoundingClientRect();

      if (pos !== "fixed" && pos !== "absolute") continue;
      const coversViewport =
        rect.width  >= window.innerWidth  * 0.8 &&
        rect.height >= window.innerHeight * 0.8;
      if (!coversViewport) continue;

      if (pe === "none" && opacity < 1 && !isNaN(z) && z > 500) {
        // Classic click-absorbing trap.
        findings.push("Likely overlay trap with disabled pointer-events");
        score += 25;
        break; // one is enough — don't double-penalize
      }
      if (!isNaN(opacity) && opacity < 0.1 && !isNaN(z) && z > 5000) {
        findings.push("Fully transparent high-z overlay element");
        score += 25;
        break;
      }
    }

    /* ------------------------------------------------------ *
     *  Hidden buttons: zero-size or off-screen <button> tags
     *  that could capture clicks without the user noticing.
     * ------------------------------------------------------ */
    const buttons = document.querySelectorAll("button, a[role=button], input[type=button]");
    let hiddenButtons = 0;
    buttons.forEach(b => {
      const s = window.getComputedStyle(b);
      if (s.visibility === "hidden" || s.display === "none" || num(s, "opacity") === 0) {
        hiddenButtons++;
      }
    });
    if (hiddenButtons > 0) {
      findings.push(`${hiddenButtons} hidden interactive element(s)`);
      // display:none buttons are everywhere in legitimate UI (menus, modals,
      // accordions, responsive breakpoints). This alone should never cross
      // the Suspicious threshold (25) — it only meaningfully adds risk when
      // combined with an actual iframe/overlay signal detected above.
      score += Math.min(15, hiddenButtons * 3);
    }

    score = Math.max(0, Math.min(100, Math.round(score)));

    let label = "Safe";
    if (score >= 60) label = "Danger";
    else if (score >= 25) label = "Suspicious";

    return { score, weight: 100, label, findings };
  }

  window.WebShieldDetectors = window.WebShieldDetectors || {};
  window.WebShieldDetectors.clickjacking = { run };
})();
