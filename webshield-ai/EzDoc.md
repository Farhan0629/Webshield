# WebShield AI — Simple & Easy Project Guide (EzDoc)

Welcome! This guide explains **WebShield AI** in simple, plain English without complicated code snippets, pseudocode, or hard technical jargon. If you want to understand how your extension works under the hood like explaining it to a friend, this document is for you!

---

## Table of Contents

1. [What is WebShield AI & Why Was It Built?](#1-what-is-webshield-ai--why-was-it-built)
2. [How Does a Chrome Extension Work? (The Basics)](#2-how-does-a-chrome-extension-work-the-basics)
3. [The Big Picture: How WebShield AI Protects You](#3-the-big-picture-how-webshield-ai-protects-you)
4. [Folder & File Guide (What Every Part Does)](#4-folder--file-guide-what-every-part-does)
5. [The 7 Security Detectors Explained Simply](#5-the-7-security-detectors-explained-simply)
   - 5.1 [DOM XSS Detector (Unsafe Page Injection)](#51-dom-xss-detector-unsafe-page-injection)
   - 5.2 [Clickjacking Detector (Invisible Trap Overlays)](#52-clickjacking-detector-invisible-trap-overlays)
   - 5.3 [Malicious JavaScript Detector (Hidden & Obfuscated Code)](#53-malicious-javascript-detector-hidden--obfuscated-code)
   - 5.4 [Cookie Theft Detector (Session & Password Stealing)](#54-cookie-theft-detector-session--password-stealing)
   - 5.5 [Crypto Miner Detector (CPU Hijacking)](#55-crypto-miner-detector-cpu-hijacking)
   - 5.6 [Drive-by Download Detector (Hidden File Downloads)](#56-drive-by-download-detector-hidden-file-downloads)
   - 5.7 [Permission Snooping Detector (Camera, Mic, Location & Clipboard Probing)](#57-permission-snooping-detector-camera-mic-location--clipboard-probing)
   - 5.8 [Google Safe Browsing (Global Threat Database)](#58-google-safe-browsing-global-threat-database)
6. [How Risk Scores & Recommendations Are Calculated](#6-how-risk-scores--recommendations-are-calculated)
7. [The Extension Popup Interface (What You See on Screen)](#7-the-extension-popup-interface-what-you-see-on-screen)
8. [Why Does YouTube Show a Score of 15?](#8-why-does-youtube-show-a-score-of-15)
9. [How to Install, Test, and Use WebShield AI](#9-how-to-install-test-and-use-webshield-ai)
10. [Simple Frequently Asked Questions (FAQ)](#10-simple-frequently-asked-questions-faq)
11. [Summary](#11-summary)

---

## 1. What is WebShield AI & Why Was It Built?

### What is it?
**WebShield AI** is an intelligent security assistant that lives inside your Google Chrome web browser. Whenever you open a web page, WebShield AI instantly inspects the website in the background to see if it is trying to perform sneaky or malicious actions on your computer.

### Why was it built?
When you visit websites, your browser runs JavaScript code written by the website owners. While most websites use code to display nice buttons and videos, bad websites can use code to:
- Secretly access your location, camera, or microphone without asking again.
- Steal your saved login cookies and send them to a hacker.
- Secretly download hidden `.exe` virus files onto your laptop.
- Use your computer's CPU power to mine cryptocurrency, making your fan spin loud and draining your battery.
- Cover the screen with invisible trap buttons so clicking anywhere opens spam.

WebShield AI acts as your personal security guard inside Chrome. It watches the website's code in real time, assigns a safety score, and warns you if a website is acting suspiciously.

---

## 2. How Does a Chrome Extension Work? (The Basics)

Think of a Chrome Extension as a small application with three main team members working together:

1. **The Inspector (Content Script - `content.js`)**:  
   This script lives inside the web page you are viewing. Its job is to read the page's HTML structure, look at the JavaScript code running on the page, and check if buttons or links are hidden.

2. **The Coordinator (Background Service Worker - `background.js`)**:  
   This runs in the background behind the scenes. It receives reports from the Inspector, remembers previous safety scores for each open tab, and talks to Google's online database to check if a website URL is known to be dangerous.

3. **The Display Screen (Popup Interface - `popup/`)**:  
   This is what pops up when you click the WebShield AI icon in your browser toolbar. It displays colorful status cards (`Safe`, `Caution`, `Warning`, `Critical`), sensor indicators, and advice on what to do.

---

## 3. The Big Picture: How WebShield AI Protects You

Here is the step-by-step story of what happens every time you open a website:

1. **You open a website** (e.g., `example.com`).
2. **WebShield AI starts inspecting immediately**: Before the website even finishes loading, WebShield AI's detectors look at the page elements and set up safety traps.
3. **Detectors collect clues**: The 7 local detectors check for hidden downloads, camera/mic access, stolen cookies, and obfuscated code.
4. **Scores are calculated**: Each detector assigns a score from 0 (completely safe) to 100 (very dangerous).
5. **Report sent to the popup**: If you click the WebShield AI icon, the popup displays whether the website is safe or dangerous and gives clear recommendations (e.g., *"Leave this website immediately"*).

---

## 4. Folder & File Guide (What Every Part Does)

Here is every file in your project explained simply:

```text
webshield-ai/
├── manifest.json              --> The identity card and settings file of the extension.
├── background.js              --> The background orchestrator and Google Safe Browsing coordinator.
├── content.js                 --> The main page scanner that runs inside every tab.
├── README.md                  --> Brief project introduction file.
├── DOCUMENTATION.md           --> Complete technical developer manual.
├── EzDoc.md                   --> This simple, easy-to-read guide!
│
├── assets/                    --> Contains the shield icons shown in Chrome.
│   └── icons/                 --> 16x16, 48x48, and 128x128 pixel icon images.
│
├── popup/                     --> What you see when clicking the extension icon.
│   ├── popup.html             --> The layout structure of the popup menu.
│   ├── popup.css              --> The dark-blue glassmorphic visual theme.
│   └── popup.js               --> The script that updates the popup cards and buttons.
│
├── options/                   --> The settings page.
│   ├── options.html           --> The settings window layout.
│   ├── options.css            --> Settings page styles.
│   └── options.js             --> Saves your optional Google Safe Browsing API key.
│
└── utils/                     --> The brain of the extension.
    ├── riskEngine.js          --> Turns technical scores into clear advice and risk labels.
    └── detectors/             --> The 7 security detection modules:
        ├── domScanner.js      --> Checks for dangerous website code manipulation (XSS).
        ├── clickjacking.js    --> Checks for invisible overlay traps.
        ├── scriptAnalyzer.js  --> Checks for scrambled or hidden JavaScript code.
        ├── cookieMonitor.js   --> Checks if a site is trying to steal your login cookies.
        ├── cryptoMiner.js     --> Checks if a site is secretly mining crypto on your CPU.
        ├── downloadMonitor.js --> Checks for hidden automatic file downloads.
        └── permissionSnooper.js-> Checks if a site is secretly reading your location, mic, or clipboard.
```

---

## 5. The 7 Security Detectors Explained Simply

### 5.1 DOM XSS Detector (`domScanner.js`)
- **What it checks**: Checks if the website is using risky code commands like `eval()` or injecting raw text directly into the page (`innerHTML`).
- **Why it matters**: Hackers can use these commands to force your browser to execute unauthorized code.
- **How it works**: It scans the web page code for dangerous commands. If it finds risky syntax, it flags a warning.

### 5.2 Clickjacking Detector (`clickjacking.js`)
- **What it checks**: Checks if the website has placed invisible boxes or transparent frames (`<iframe>`) over the screen.
- **Why it matters**: A trick website might show a harmless button like "Play Game", but layer an invisible button over it so clicking "Play Game" actually clicks "Transfer Money" or "Like Page".
- **How it works**: It measures element transparency (`opacity: 0`) and layer position (`z-index`). If an element is completely invisible yet covers the screen, it flags Clickjacking.

### 5.3 Malicious JavaScript Detector (`scriptAnalyzer.js`)
- **What it checks**: Checks if the JavaScript running on the web page is heavily scrambled, obfuscated, or hidden using encoding tricks like `atob()` (Base64) or `String.fromCharCode()`.
- **Why it matters**: Normal websites write clean code so browsers can read it. Cybercriminals scramble their code to hide virus payloads from security tools.
- **How it works**: It inspects JavaScript files. If a script contains multiple layers of scrambled text and dynamic execution commands, it flags it as Malicious JS.

### 5.4 Cookie Theft Detector (`cookieMonitor.js`)
- **What it checks**: Checks if a script reads your saved cookies (`document.cookie`) and immediately transmits them to a different website address.
- **Why it matters**: Cookies store your logged-in session tokens for websites like email or banking. If an attacker reads your cookies and sends them to their own server, they can log into your account without your password.
- **How it works**: It attaches a secret listener to your cookies. If a script reads a cookie and makes a background request to a third-party server within 3 seconds, it flags Cookie Theft.

### 5.5 Crypto Miner Detector (`cryptoMiner.js`)
- **What it checks**: Checks if a website is secretly spawning background Web Workers to run heavy mathematical loops used in cryptocurrency mining (like CoinHive).
- **Why it matters**: Rogue websites use your computer's processor to earn crypto for themselves, making your computer freeze, lag, and overheat.
- **How it works**: It monitors background workers created by the page and scans for cryptomining signatures (`hashesPerSecond`, `Cryptonight`). If found, it flags Crypto Miner.

### 5.6 Drive-by Download Detector (`downloadMonitor.js`)
- **What it checks**: Checks if a website contains hidden download links configured to automatically download executable files (`.exe`, `.bat`, `.vbs`, `.zip`).
- **Why it matters**: Malicious sites try to download viruses onto your computer automatically without you clicking "Save".
- **How it works**: It looks for links pointing to executable files that have CSS rules making them hidden from view (`display: none`). If found, it flags Drive-by Download.

### 5.7 Permission Snooping Detector (`permissionSnooper.js`)
- **What it checks**: Checks if a website is actively reading your Geolocation (GPS), Clipboard (copied text), Camera, Microphone, or Notification permissions.
- **Why it matters**: If you previously granted "Always Allow" location access to a site, the site can secretly track your location every time you visit without showing a pop-up prompt.
- **How it works**: It attaches smart wrappers to browser sensors (`navigator.geolocation`, `navigator.clipboard`, `getUserMedia`). Whenever the page reads your location or clipboard, WebShield AI records the event and updates the sensor counter in real time.

### 5.8 Google Safe Browsing (Global Threat Database)
- **What it checks**: Checks the website's web address (URL) against Google's official online database of known scam and phishing sites.
- **Why it matters**: Gives you a second opinion backed by Google's global security team.
- **How it works**: `background.js` sends the web address to Google's Safe Browsing API. If Google lists the URL as dangerous, it flags Safe Browsing.

---

## 6. How Risk Scores & Recommendations Are Calculated

Every detector calculates a numerical score between **0** (completely safe) and **100** (extremely dangerous).

### The 3 Safety Bands:
- **0 to 20**: **Safe** (Green) — No threats detected.
- **21 to 54**: **Suspicious** (Yellow/Orange) — Potential risk detected; exercise caution.
- **55 to 100**: **Danger** (Red) — Severe threat detected; leave the page immediately.

### Simple Recommendations
The **Risk Engine** (`riskEngine.js`) looks at all 7 detectors. If any detector reports `Danger` or `Suspicious`, it generates easy-to-understand advice in plain English, such as:
- *"Close this page — it uses dangerous DOM sinks."*
- *"This page is accessing your camera, microphone, or location. Revoke permissions and close this site now."*
- *"Leave this website immediately if you did not expect to land here."*

---

## 7. The Extension Popup Interface (What You See on Screen)

When you click the WebShield AI icon in Chrome, you see a clean dark-blue dashboard divided into 5 simple parts:

1. **Header Bar**: Shows the domain name of the current website and a Settings gear icon.
2. **Status Banner**: Displays the main safety verdict (`All Clear`, `Caution`, `Warning`, `Critical`) and how many detectors were triggered (e.g., `2 of 8 detectors flagged`).
3. **Detected Behaviors Grid**: 8 cards representing the 8 security detectors, each displaying `Safe`, `Suspicious`, or `Danger`.
4. **Sensors Accessed Panel**: Displays real-time counts if the site accesses your Location, Clipboard, Mic, or Camera.
5. **Recommendations & Action Buttons**: Displays safety advice, a **Refresh Scan** button to re-scan, and a **Trust this site** toggle switch to pause scanning on trusted sites.

---

## 8. Why Does YouTube Show a Score of 15?

If you open WebShield AI on `youtube.com`, you might notice `Clickjacking` displays a score of **15/100 (Safe)**.

### Is YouTube dangerous?
**No!** YouTube is completely safe.

### Why does it show 15?
YouTube is a massive website with many hidden menus (like the side drawer menu, share popup, video quality settings, and caption options).

To keep these menus hidden until you click on them, YouTube sets their buttons to `display: none` or `visibility: hidden` in the CSS styling.

WebShield AI's Clickjacking detector counts hidden buttons. Each hidden button adds 3 small points, capped at a maximum of **15 points**.

Because 15 points is below 25 (the Suspicious threshold), WebShield AI marks YouTube as **Safe**. The score of 15 is just normal background activity from YouTube's dropdown menus!

---

## 9. How to Install, Test, and Use WebShield AI

### Step 1: Open Extensions in Chrome
Type `chrome://extensions` in your Chrome address bar and press Enter.

### Step 2: Turn On Developer Mode
Click the **Developer mode** toggle switch in the top-right corner.

### Step 3: Load the Extension
1. Click the **Load unpacked** button in the top-left corner.
2. Select your project folder:
   `C:\Users\FARHAN\OneDrive\Desktop\Websheild\webshield-ai`

### Step 4: Test with the Fixture Page
1. Open the included `test-page.html` file in Chrome.
2. Click the **`⚡ Trigger ALL 7 Threats Now`** button on the test page.
3. Click the WebShield AI extension icon in your toolbar — you will see a **Critical Warning** showing all threat cards flagged!

---

## 10. Simple Frequently Asked Questions (FAQ)

#### Q1: Does WebShield AI slow down my browsing?
**No.** All scanning happens asynchronously in background micro-seconds without blocking page rendering.

#### Q2: Are my passwords or data sent to remote servers?
**No.** All 7 behavioral detectors run 100% locally inside your own browser.

#### Q3: What happens if I don't add a Google Safe Browsing API key?
WebShield AI simply skips the online Google check and relies entirely on its 7 local detectors.

#### Q4: Why does a site show "Suspicious" instead of "Danger"?
Suspicious means the site uses unusual patterns (like reading clipboard text or using hidden buttons), but hasn't confirmed a severe attack yet.

#### Q5: Can I trust a site manually?
Yes! Flip the **Trust this site** switch in the popup menu to turn off scanning for that domain.

---

## 11. Summary

**WebShield AI** is your smart, local browser guardian. It requires no complex technical setup, respects your complete privacy by inspecting pages locally, and translates technical security risks into clear, color-coded warnings so you can browse the web safely!
