# WebShield AI 🛡️

> A lightweight, fully local browser security assistant for Google Chrome
> (Manifest V3). Monitors the current webpage for suspicious behaviours commonly
> associated with web attacks and assigns an overall **Risk Score**.

![WebShield AI](docs/banner.png)

---

## 📋 Project Description

WebShield AI is a Chrome extension that watches the page you are currently
visiting and analyses it for indicators of common browser-side attacks:

- **DOM-based Cross-Site Scripting (XSS)** sinks
- **Clickjacking** via hidden iframes and overlay traps
- **Malicious / obfuscated JavaScript**
- **Cookie theft** through exfiltration channels
- **Browser-side cryptominers**
- **Drive-by download** patterns

Each detector is independent and read-only — the extension never modifies the
page, never executes suspect code, and sends nothing to any backend. All
detection logic runs **locally inside the browser** via a content script and a
service worker.

The goal is **not** to claim 100% accuracy. The goal is to surface suspicious
signals and translate them into a 0–100 Risk Score that is easy to read at a
glance.

---

## ✨ Features

| Feature                    | Description                                                                  |
| -------------------------- | ---------------------------------------------------------------------------- |
| **Real-time scanning**     | Every page is analysed as soon as the content script loads.                  |
| **Risk Score (0–100)**     | Combined and capped score from all six detectors with a diminishing-returns curve. |
| **Threat Level band**      | Safe / Low / Medium / High / Critical with neon colour mapping.              |
| **Circular progress ring** | Animated SVG ring in the popup that reflects current score and colour.       |
| **Threat cards**           | Six status cards, one per detector, with green/yellow/red indicators.        |
| **Recommendations**        | Plain-English next steps driven by the detected threats.                     |
| **Live statistics**        | Number of scripts scanned and number flagged as suspicious.                  |
| **Refresh Scan button**    | Run a fresh scan on-demand from the popup.                                   |
| **Loading animation**      | Smooth scanner ring animation on popup open.                                 |
| **Fully offline**          | No backend, no telemetry, no external network calls.                         |

---

## 🗂️ Folder Structure

```
webshield-ai/
├── manifest.json              # Manifest V3 config (permissions, scripts, popup)
├── background.js              # Service worker: message router + per-tab cache
├── content.js                 # Injected into every page; runs all detectors
├── README.md                  # You are here
│
├── popup/
│   ├── popup.html             # Popup layout
│   ├── popup.css              # Dark cybersecurity theme
│   └── popup.js               # Renders scores, cards, recommendations
│
├── utils/
│   ├── riskEngine.js          # Combines detector scores into the final score
│   └── detectors/
│       ├── domScanner.js      # Detector 1 — DOM XSS
│       ├── clickjacking.js    # Detector 2 — Clickjacking
│       ├── scriptAnalyzer.js  # Detector 3 — Malicious JS / obfuscation
│       ├── cookieMonitor.js   # Detector 4 — Cookie theft
│       ├── cryptoMiner.js     # Detector 5 — Cryptominer activity
│       └── downloadMonitor.js # Detector 6 — Drive-by downloads
│
└── assets/
    └── icons/
        ├── icon16.png
        ├── icon48.png
        └── icon128.png
```

---

## 🧠 How It Works

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  Browser Tab                                                                 │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Page DOM                                                            │   │
│  │                                                                      │   │
│  │   ┌──────────────────── content.js ─────────────────────┐            │   │
│  │   │  • waits for document_idle                          │            │   │
│  │   │  • runs all six detectors                           │            │   │
│  │   │  • combines scores via riskEngine.js                │            │   │
│  │   └──────────────────────────────┬─────────────────────┘            │   │
│  │                                  │  chrome.runtime.sendMessage       │   │
│  └──────────────────────────────────┼──────────────────────────────────┘   │
│                                     v                                       │
│  ┌──────────────────────── background.js (service worker) ─────────────┐   │
│  │  • stores latest scan per tab                                      │   │
│  │  • responds to popup requests                                       │   │
│  │  • broadcasts updates to an open popup                              │   │
│  └───────────────────────────────────┬──────────────────────────────────┘   │
│                                      v                                      │
│  ┌──────────────────────── popup.js (extension popup) ─────────────────┐    │
│  │  • renders circular ring + meter number                            │    │
│  │  • updates threat cards, recommendations, stats                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Detector pipeline

Each detector returns `{ score: 0..100, weight: 100, label: "Safe"|"Suspicious"|"Danger", findings: [] }`.

`riskEngine.combine(weights, totals)` blends them using a weighted-sum with a
`sqrt`-style diminishing-returns curve, so that a single catastrophic signal
still drives the overall score strongly, while many small "yellow" flags do
not trivially max it out.

| Score | Threat level | Colour |
| ----- | ------------ | ------ |
| 0–20  | **Safe**     | 🟢 Green  |
| 21–40 | **Low**      | 🟡 Yellow |
| 41–60 | **Medium**   | 🟠 Orange |
| 61–80 | **High**     | 🔴 Red    |
| 81–100| **Critical** | 🔴 Dark Red |

### Per-detector methodology (summary)

| # | Detector            | What it looks for                                                                                     |
| - | ------------------- | ----------------------------------------------------------------------------------------------------- |
| 1 | **DOM XSS**         | `eval`, `new Function`, `setTimeout("…")`, `setInterval("…")`, `innerHTML`, `outerHTML`, `document.write`, combined with URL-derived sources like `location.hash`. |
| 2 | **Clickjacking**    | Invisible / fullscreen iframes, zero-size iframes, full-viewport fixed overlays with disabled pointer events, hidden `<button>`s. |
| 3 | **Malicious JS**    | `eval`, `atob`, `btoa`, `new Function`, `Function(`, `WebAssembly`, `navigator.plugins`, `navigator.hardwareConcurrency`, `document.cookie`, plus obfuscation heuristics (long base64, hex blobs, escaped-char density, high-entropy windows). |
| 4 | **Cookie Theft**    | Read-only observation hooks on `document.cookie`, `fetch`, `XMLHttpRequest`, `navigator.sendBeacon`, plus MutationObserver for injected hidden `<form>`s. |
| 5 | **Crypto Miner**    | Known miner-library keywords (CoinHive, CryptoLoot, …), `WebAssembly` + hash algorithm keywords, short-period `setInterval`s, tight `while(true)` loops, blob/data-URI `Worker`s. |
| 6 | **Drive-by**        | `<a download>` elements, hidden download anchors, blob/data-URI anchors, hidden iframes pointed at executable URLs, observed `Content-Disposition: attachment` responses. |

---

## 📦 Installation

Because the extension is unpacked, you load it via Chrome's developer mode.

1. **Download or clone** this repository to your machine.
2. Open Google Chrome and visit `chrome://extensions/`.
3. Toggle **Developer mode** (top right) to ON.
4. Click **Load unpacked**.
5. Select the **`webshield-ai`** folder (the one containing `manifest.json`).
6. The WebShield AI icon will appear in your toolbar. Click it on any tab to
   see the risk meter.

> If you make changes to the code, click the **↻ Reload** button on the
> extension card to refresh it. Use the **Refresh Scan** button inside the
> popup to re-run detection on the current page.

---

## 🖼️ Screenshots

> Placeholder — drop your own screenshots into a `docs/` folder and reference
> them here.

| Popup                                                |
| ---------------------------------------------------- |
| ![Popup placeholder](docs/screenshot-popup.png)      |

```
┌──────────────────────────────────────┐
│  ░ WebShield AI       github.com    │
│  Current site: example.com           │
│                                      │
│           ╭───────────╮              │
│           │     34    │              │
│           │  / 100    │              │
│           │  Risk     │              │
│           ╰───────────╯              │
│             Low                      │
│                                      │
│  DOM XSS          Safe        ✓     │
│  Clickjacking     Safe        ✓     │
│  Malicious JS     Suspicious  ⚠     │
│  Cookie Theft     Safe        ✓     │
│  Crypto Miner     Safe        ✓     │
│  Drive-by Dl      Safe        ✓     │
│                                      │
│  Recommendations                     │
│  ▸ Unusual JavaScript patterns …    │
│                                      │
│  Scripts: 12  Suspect: 2  14:02:11   │
│                                      │
│   [ ⟳ Refresh Scan ]  [ Close ]     │
└──────────────────────────────────────┘
```

---

## 🔮 Future Improvements

- **ML-based classification** — train a lightweight model on labelled JS
  samples to catch novel obfuscation patterns.
- **Domain reputation** — cross-reference URLs against a local blocklist of
  known-phishing hosts.
- **CSP / Permissions-Policy analyser** — flag pages that grant overly broad
  capabilities to scripts.
- **Per-site learning** — adapt baselines per origin so internal admin tools
  with lots of `eval` don't noise-spam the UI.
- **Optional opt-in telemetry** — anonymised, opt-in only, used solely to
  improve detection quality.
- **Exportable report** — one-click "send me a PDF summary of this scan".
- **Firefox port** — the entire pipeline is plain JS + Manifest V3-friendly,
  requiring only minor manifest tweaks.

---

## ⚖️ Disclaimer

This extension is a proof-of-concept academic project. It surfaces *suspected*
indicators of compromise using heuristic static analysis only. It is **not** a
substitute for a real antivirus, EDR, or professional security audit. Always
verify findings manually before taking action.

---

## 📝 License

Released for educational use. Feel free to fork and adapt.
