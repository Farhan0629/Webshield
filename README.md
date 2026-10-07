<p align="center">
  <img src="assets/banner.png" alt="WebShield AI Banner" width="100%" />
</p>

<p align="center">
  <strong>An intelligent, lightweight browser security assistant engineered for Google Chrome (Manifest V3).</strong><br>
  Real-time client-side threat detection, privacy snooping prevention, and unified risk scoring.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Chrome_Extension-Manifest_V3-4285F4?style=for-the-badge&logo=google-chrome&logoColor=white" alt="Manifest V3" />
  <img src="https://img.shields.io/badge/Security_Engines-7_Detectors-00E5FF?style=for-the-badge&logo=shield&logoColor=black" alt="7 Detectors" />
  <img src="https://img.shields.io/badge/Safe_Browsing-API_v4_Integrated-34A853?style=for-the-badge&logo=google&logoColor=white" alt="Safe Browsing" />
  <img src="https://img.shields.io/badge/Privacy-100%25_Local_Analysis-10B981?style=for-the-badge&logo=lock&logoColor=white" alt="100% Local" />
  <img src="https://img.shields.io/badge/License-MIT-purple?style=for-the-badge" alt="License" />
</p>

---

## 🛡️ Overview

Modern websites execute billions of lines of untrusted client-side JavaScript inside browser tabs. Traditional perimeter defenses (DNS filters, external firewalls, static blocklists) are blind to attacks executing inside the browser DOM.

**WebShield AI** is an advanced browser security extension that monitors page behavior in real time, identifies indicators of compromise (IoCs), intercepts predatory hardware snooping, and synthesizes findings into an intuitive **0–100 Risk Score**.

All heuristic detection operates **100% locally** inside your browser with zero latency penalty and zero privacy overhead.

---

## ⚡ Core Features

- **Real-Time Automated Page Auditing**: Evaluates security posture immediately at `document_start` and dynamically monitors mutations.
- **7 Modular Local Security Engines**: Specialized heuristic detectors targeting real-world attack vectors.
- **Hardware & Sensor Privacy Panel**: Live indicators exposing unauthorized probing or continuous usage of camera, microphone, geolocation, and clipboard.
- **Dual-Layer Threat Verification**: Local static heuristics paired with optional **Google Safe Browsing v4** threat intelligence.
- **Intelligent Risk Scoring Engine**: Non-linear, weighted scoring curve that avoids false-positive alarm fatigue while escalating critical single threats.
- **Cybersecurity Glassmorphic Dashboard**: Dark cyberpunk UI with circular score meters, threat cards, script diagnostics, and actionable safety recommendations.
- **Domain Trust Management**: Whitelist known developer environments or internal corporate dashboards with a single toggle.
- **Zero Cloud Telemetry**: Your browsing history, cookies, and page content never leave your device.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             BROWSER TAB                                     │
│                                                                             │
│   ┌─────────────────────────── Page DOM ────────────────────────────────┐   │
│   │                                                                     │   │
│   │   ┌──────────────── content.js (document_start) ────────────────┐   │   │
│   │   │  • Injects into isolated execution context                   │   │   │
│   │   │  • Orchestrates 7 specialized detection engines              │   │   │
│   │   │  • Observes DOM mutations, API calls, and inline scripts     │   │   │
│   │   │  • Aggregates heuristics via riskEngine.js                   │   │   │
│   │   └──────────────────────────────┬──────────────────────────────┘   │   │
│   │                                  │  chrome.runtime.sendMessage      │   │
│   └──────────────────────────────────┼──────────────────────────────────┘   │
│                                      v                                      │
│   ┌──────────────── background.js (Service Worker) ─────────────────────┐   │
│   │  • Per-tab state & diagnostic caching                              │   │
│   │  • Remote script fetcher & cache manager                           │   │
│   │  • Google Safe Browsing API v4 client (optional hash check)        │   │
│   │  • Trusted sites (allowlist) management in chrome.storage.local    │   │
│   └───────────────────┬───────────────────────────────┬─────────────────┘   │
│                       │                               │                     │
│                       v                               v                     │
│   ┌──────────────── popup/ ────────────────┐  ┌──────── options/ ───────┐   │
│   │  • Glassmorphic Security HUD           │  │  • Safe Browsing Key    │   │
│   │  • Dynamic Risk Meter (0–100)          │  │  • Storage Management   │   │
│   │  • Hardware Sensor Indicators          │  └─────────────────────────┘   │
│   │  • 7 Threat Cards & Recommendations    │                                │
│   └────────────────────────────────────────┘                                │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔬 The 7 Security Detectors

| # | Engine | Target Threat Vector | Detection Methodology |
|---|---|---|---|
| 1 | **DOM XSS Scanner** | Cross-Site Scripting Injection | Identifies unsafe JavaScript sinks (`innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout`) that ingest unsanitized user-controlled sources (`location.search`, `location.hash`, `document.referrer`, `window.name`). |
| 2 | **Clickjacking Guard** | UI Redressing & Overlay Traps | Detects invisible iframes (`opacity: 0`), zero-dimension frames, absolute viewport-covering elements with pointer-event traps, and hidden overlay layers designed to hijack user clicks. |
| 3 | **Malicious JS Analyzer** | Obfuscation & Exploit Scripts | Computes Shannon entropy on inline scripts, flags anomalous density of hex/unicode escapes (`\x`, `\u`), ultra-long Base64 payloads, and restricted function invocations (`new Function()`, `atob`, `WebAssembly.compile`). |
| 4 | **Cookie Theft Monitor** | Session Hijacking & Credential Exfiltration | Observes read access to `document.cookie` correlated with outbound exfiltration channels including `fetch()`, `XMLHttpRequest`, `navigator.sendBeacon()`, image ping beacons, and dynamically inserted hidden forms. |
| 5 | **Cryptominer Shield** | CPU Hijacking & Cryptojacking | Matches known cryptomining library signatures (CoinHive, CryptoLoot, WebMinePool), detects WebAssembly cryptographic mining routines, aggressive worker thread spawns, and tight unthrottled execution loops. |
| 6 | **Drive-by Download Guard** | Stealth Executables & Malware Delivery | Monitors automatic programmatic clicks on hidden `<a download>` anchors, unauthorized Blob/Data-URI generation, and suspicious payload file extensions (`.exe`, `.scr`, `.bat`, `.vbs`, `.ps1`, `.apk`, `.iso`). |
| 7 | **Permission Snooper** | Silent Hardware & Sensor Abuse | Intercepts unprompted polling or active snooping against sensitive browser APIs: Geolocation, Microphone, Camera, Clipboard read (`readText`), Notifications, Device Enumeration, USB, MIDI, and Wake Locks. |

---

## 🌐 Google Safe Browsing Integration

In addition to local behavioral heuristics, WebShield AI supports **Google Safe Browsing API v4** for global threat reputation lookup:

- **Threat Coverage**: Verifies target hostnames against Google's global databases for `MALWARE`, `SOCIAL_ENGINEERING` (phishing), `UNWANTED_SOFTWARE`, and `POTENTIALLY_HARMFUL_APPLICATION`.
- **Privacy-Preserving**: Only queries hostnames; page contents, user form data, and cookies are never transmitted.
- **Smart Local Caching**: Hostname verdicts are cached in-memory with a 10-minute TTL to reduce API usage and maintain zero page latency.
- **Optional**: Operates out-of-the-box without an API key using pure local heuristics. Users can configure a free key in the Options page for double-layer verification.

---

## 📊 Risk Engine & Scoring Methodology

The risk calculation combines scores from all 7 detectors using a diminishing-returns mathematical model:

$$\text{Blended Score} = \min\left(100, \; \sqrt{\sum \text{Score}_i^2 \times \text{Weight}_i}\right)$$

This mathematical approach guarantees:
1. **Critical Threat Priority**: A single critical danger (e.g. active cryptominer or drive-by download) immediately escalates the overall threat level.
2. **False Positive Dampening**: Minor benign signals across multiple detectors do not trivially trigger severe alarms.

### Threat Level Bands

| Risk Score | Threat Level | Visual Indicator | Status Meaning |
|:---:|:---:|:---:|:---|
| **0 – 20** | **Safe** | 🟢 Green | Normal web application behavior; no anomalous indicators detected. |
| **21 – 40** | **Low** | 🟡 Yellow | Minor telemetry or permission checks noticed; standard browsing caution. |
| **41 – 60** | **Medium** | 🟠 Orange | Suspicious script obfuscation or potential tracking patterns identified. |
| **61 – 80** | **High** | 🔴 Red | High likelihood of hostile scripts, clickjacking overlays, or credential access. |
| **81 – 100** | **Critical** | 🚨 Crimson | Active malicious activity detected (malware download, cryptominer, exploit sink). |

---

## 📁 Repository Structure

```
Webshield/
├── manifest.json              # Chrome Manifest V3 manifest & configuration
├── background.js              # Service Worker: event dispatcher, cache, Safe Browsing client
├── content.js                 # Content script orchestrator injected into all web tabs
├── README.md                  # Comprehensive documentation and project guide
├── .gitignore                 # Git ignore file for development artifacts
│
├── assets/
│   ├── banner.png             # Official high-resolution project banner
│   └── icons/
│       ├── icon16.png         # Extension toolbar icon (16x16)
│       ├── icon48.png         # Extension manager icon (48x48)
│       └── icon128.png        # Web Store presentation icon (128x128)
│
├── popup/
│   ├── popup.html             # Glassmorphic extension HUD markup
│   ├── popup.css              # Cyberpunk cybersecurity stylesheet
│   └── popup.js               # Reactive UI controller & state renderer
│
├── options/
│   ├── options.html           # Settings interface for Safe Browsing configuration
│   └── options.js             # Options storage controller (chrome.storage.local)
│
└── utils/
    ├── riskEngine.js          # Heuristic aggregation, score weighting, and recommendations
    └── detectors/             # Independent modular security engines
        ├── domScanner.js      # Detector 1: DOM XSS sinks & sources
        ├── clickjacking.js    # Detector 2: Hidden frames & click traps
        ├── scriptAnalyzer.js  # Detector 3: Script entropy & obfuscated code
        ├── cookieMonitor.js   # Detector 4: Cookie access & exfiltration
        ├── cryptoMiner.js     # Detector 5: In-browser cryptocurrency mining
        ├── downloadMonitor.js # Detector 6: Unauthorized drive-by downloads
        └── permissionSnooper.js # Detector 7: Hardware & privacy API snooping
```

---

## 🚀 Installation & Setup

Because WebShield AI is an unpacked Manifest V3 developer project, you can install it into any Chromium-based browser (Google Chrome, Brave, Microsoft Edge, Opera, Arc) in seconds:

### Step 1: Clone the Repository
```bash
git clone https://github.com/Farhan0629/Webshield.git
```

### Step 2: Load into Google Chrome
1. Open Chrome and navigate to `chrome://extensions/`.
2. In the top-right corner, switch the **Developer mode** toggle to **ON**.
3. Click the **Load unpacked** button in the top-left corner.
4. Select the project folder (`Webshield`) containing `manifest.json`.
5. The **WebShield AI** icon will appear in your extensions list and browser toolbar.

### Step 3: (Optional) Setup Google Safe Browsing
1. Right-click the WebShield AI extension icon and select **Options** (or click the Settings gear in the popup).
2. Follow the link to obtain a free [Google Safe Browsing API Key](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com).
3. Paste the API key into the field and click **Save**.

---

## 🧪 Testing & Verification

You can test WebShield AI's detectors on benign test sites and developer test fixtures:

- **Hardware Privacy**: Visit any web conferencing or map site (e.g., Google Maps) and observe the **Hardware & Sensors** chips light up showing active or queried location/media APIs.
- **Obfuscation Detection**: Visit sites with packed scripts to observe the Malicious JS detector evaluating entropy and base64 density.
- **Clickjacking Simulation**: Create a local HTML page containing a transparent iframe covering a button to test the Clickjacking overlay detector.
- **Safe Browsing Test**: Enter official Safe Browsing test URIs (such as `http://malware.testing.google.test/testing/malware/`) to verify ground-truth reputation alerts.

---

## 🔒 Privacy Guarantee

- **No Third-Party Telemetry**: WebShield AI contains zero trackers, zero Google Analytics, and zero remote logging.
- **No Keystroke or Form Harvesting**: Form inputs, passwords, and user typing are never recorded.
- **Strictly Local Heuristics**: Page DOM inspection, regex scanning, and entropy analysis occur strictly inside the content script's isolated memory space.

---

## 🤝 Contributing

Contributions, bug reports, and suggestions are welcome!
1. Fork the repository (`https://github.com/Farhan0629/Webshield.git`).
2. Create your feature branch (`git checkout -b feature/NewDetector`).
3. Commit your modifications (`git commit -m "Add new detection heuristic"`).
4. Push to your branch (`git push origin feature/NewDetector`).
5. Open a Pull Request.

---

## ⚖️ Disclaimer

*WebShield AI is a heuristic cybersecurity tool designed to assist users in detecting common client-side threats and suspicious web patterns. Heuristic static analysis may occasionally produce false positives or false negatives on highly dynamic web platforms. It is intended as an additional layer of security and not as a sole substitute for full-system antivirus solutions.*

---

## 📄 License

This project is licensed under the **MIT License**. Feel free to use, modify, and build upon it.
