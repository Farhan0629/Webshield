const scanCache = {};

const SB_API_KEY_STORAGE_KEY = "webshield_sb_api_key";
const TRUSTED_SITES_KEY = "webshield_trusted_sites";
const SB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

const sbCache = {};
const SB_CACHE_TTL_MS = 10 * 60 * 1000;

const DETECTOR_NAMES = [
  "DOM XSS", "Clickjacking", "Malicious JS", "Cookie Theft",
  "Crypto Miner", "Drive-by Download", "Permission Snooping"
];

function getStoredApiKey() {
  return new Promise((resolve) => {
    chrome.storage.local.get([SB_API_KEY_STORAGE_KEY], (res) => {
      resolve((res && res[SB_API_KEY_STORAGE_KEY]) || "");
    });
  });
}

function getTrustedSites() {
  return new Promise((resolve) => {
    chrome.storage.local.get([TRUSTED_SITES_KEY], (res) => {
      resolve((res && res[TRUSTED_SITES_KEY]) || []);
    });
  });
}

function setTrustedSites(sites) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [TRUSTED_SITES_KEY]: sites }, resolve);
  });
}

async function checkSafeBrowsing(pageUrl, subResourceUrls) {
  // Build the full URL list, deduplicated.
  const allUrls = [pageUrl];
  if (Array.isArray(subResourceUrls)) {
    for (const u of subResourceUrls) {
      if (u && u.startsWith("http") && !allUrls.includes(u)) allUrls.push(u);
    }
  }

  // Check per-hostname cache.
  const hosts = new Set();
  for (const u of allUrls) {
    try { hosts.add(new URL(u).hostname); } catch (_) {}
  }
  const allCached = [...hosts].every(h => {
    const c = sbCache[h];
    return c && c.expiresAt > Date.now() && c.verdict === "clean";
  });
  const anyMaliciousCached = [...hosts].some(h => {
    const c = sbCache[h];
    return c && c.expiresAt > Date.now() && c.verdict === "malicious" && c.matches;
  });
  if (allCached) return { verdict: "clean", matches: [] };
  if (anyMaliciousCached) {
    // Re-use first malicious cache entry found.
    for (const h of hosts) {
      const c = sbCache[h];
      if (c && c.verdict === "malicious" && c.matches) return { verdict: "malicious", matches: c.matches };
    }
  }

  const apiKey = await getStoredApiKey();
  if (!apiKey) return { verdict: "unchecked", matches: [] };

  try {
    const resp = await fetch(`${SB_ENDPOINT}?key=${encodeURIComponent(apiKey)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "webshield-ai", clientVersion: "1.1.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: allUrls.map(url => ({ url }))
        }
      })
    });
    if (!resp.ok) return { verdict: "unchecked", matches: [] };
    const data = await resp.json();
    const matches = (data && Array.isArray(data.matches)) ? data.matches : [];
    const verdict = matches.length > 0 ? "malicious" : "clean";

    // Cache per-hostname.
    for (const h of hosts) {
      const hostMatches = matches.filter(m => {
        try { return new URL(m.threat && m.threat.url).hostname === h; } catch (_) { return false; }
      });
      sbCache[h] = {
        verdict: hostMatches.length > 0 ? "malicious" : "clean",
        matches: hostMatches,
        expiresAt: Date.now() + SB_CACHE_TTL_MS
      };
    }
    return { verdict, matches };
  } catch (_) {
    return { verdict: "unchecked", matches: [] };
  }
}

async function processScanResult(tabId, payload, fallbackUrl) {
  const url = payload.url || fallbackUrl || "";
  const subUrls = [].concat(payload.pageScriptUrls || [], payload.pageIframeUrls || []);
  const sbResult = url ? await checkSafeBrowsing(url, subUrls) : { verdict: "unchecked", matches: [] };

  // Treat Safe Browsing as the 8th detector.
  const totalDetectors = DETECTOR_NAMES.length + 1;
  let flaggedCount = typeof payload.flaggedCount === "number" ? payload.flaggedCount : 0;
  const threats = Object.assign({}, payload.threats || {});
  const diag = Array.isArray(payload.diag) ? payload.diag.slice() : [];

  if (sbResult.verdict === "malicious") {
    flaggedCount++;
    threats["Safe Browsing"] = "Danger";
    diag.push({
      name: "Safe Browsing",
      score: 100,
      label: "Danger",
      hitCount: (sbResult.matches || []).length
    });
  } else {
    threats["Safe Browsing"] = "Safe";
    diag.push({
      name: "Safe Browsing",
      score: 0,
      label: "Safe",
      hitCount: 0
    });
  }

  const record = {
    url,
    flaggedCount,
    totalDetectors,
    threats,
    recommendations: payload.recommendations || [],
    timestamp: payload.timestamp || Date.now(),
    scriptStats: payload.scriptStats || { total: 0, suspicious: 0 },
    permissions: payload.permissions || {},
    diag,
    safeBrowsing: sbResult.verdict,
    sbMatches: sbResult.matches || []
  };
  scanCache[tabId] = record;
  return record;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case "SCAN_RESULT": {
      const tabId = sender.tab && sender.tab.id;
      if (tabId == null) {
        sendResponse({ ok: true });
        return false;
      }
      (async () => {
        const payload = message.payload || {};
        const record = await processScanResult(tabId, payload, sender.tab && sender.tab.url);
        chrome.runtime.sendMessage({
          type: "SCAN_CACHED",
          tabId,
          payload: record
        }).catch(() => {});
        sendResponse({ ok: true });
      })();
      return true;
    }

    case "GET_LATEST_SCAN": {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs && tabs[0];
        if (!tab) {
          sendResponse({ ok: false, error: "No active tab" });
          return;
        }
        const cached = scanCache[tab.id];
        if (cached) {
          sendResponse({ ok: true, payload: cached, tabId: tab.id, url: tab.url });
          return;
        }

        const tabId = tab.id;
        const url = tab.url;

        const onScanResult = (msg, _sender, sendResp) => {
          if (_sender && _sender.tab && _sender.tab.id === tabId &&
              msg && msg.type === "SCAN_RESULT" && msg.payload) {
            chrome.runtime.onMessage.removeListener(onScanResult);
            clearTimeout(timeoutHandle);
            (async () => {
              const record = await processScanResult(tabId, msg.payload, url);
              sendResponse({ ok: true, payload: record, tabId, url });
            })();
            void sendResp;
            return false;
          }
        };
        chrome.runtime.onMessage.addListener(onScanResult);

        const timeoutHandle = setTimeout(() => {
          chrome.runtime.onMessage.removeListener(onScanResult);
          sendResponse({ ok: true, payload: null, tabId, url, scanning: true });
        }, 8000);

        try {
          chrome.tabs.sendMessage(tabId, { type: "RUN_SCAN" }, (resp) => {
            if (chrome.runtime.lastError || !resp) return;
          });
        } catch (_) {}

        void timeoutHandle;
      });
      return true;
    }

    case "REFRESH_SCAN": {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs && tabs[0];
        if (tab) chrome.tabs.sendMessage(tab.id, { type: "RUN_SCAN" });
      });
      sendResponse({ ok: true });
      return false;
    }

    case "FETCH_URL": {
      const targetUrl = message.url;
      if (!targetUrl || typeof targetUrl !== "string") {
        sendResponse({ ok: false, error: "No URL provided" });
        return false;
      }
      fetch(targetUrl, { credentials: "omit", cache: "no-store" })
        .then(r => (r.ok ? r.text() : Promise.reject(new Error("HTTP " + r.status))))
        .then(text => sendResponse({ ok: true, text }))
        .catch(err => sendResponse({ ok: false, error: String(err && err.message || err) }));
      return true;
    }

    case "IS_TRUSTED": {
      const hostname = message.hostname;
      if (!hostname) { sendResponse({ ok: false, trusted: false }); return false; }
      getTrustedSites().then(sites => {
        sendResponse({ ok: true, trusted: sites.includes(hostname) });
      });
      return true;
    }

    case "TOGGLE_TRUST": {
      const h = message.hostname;
      if (!h) { sendResponse({ ok: false }); return false; }
      (async () => {
        let sites = await getTrustedSites();
        const idx = sites.indexOf(h);
        if (idx >= 0) {
          sites.splice(idx, 1);
        } else {
          sites.push(h);
        }
        await setTrustedSites(sites);
        sendResponse({ ok: true, trusted: idx < 0 });
      })();
      return true;
    }

    default:
      sendResponse({ ok: false, error: "Unknown message type" });
      return false;
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete") {
    delete scanCache[tabId];
    chrome.tabs.sendMessage(tabId, { type: "RUN_SCAN" }, () => void 0);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete scanCache[tabId];
});

chrome.runtime.onInstalled.addListener(() => {});
