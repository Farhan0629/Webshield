/* =============================================================================
 *  WebShield AI - Options Page Script
 *  Stores the user's own Google Safe Browsing API key in chrome.storage.local
 *  under the key "webshield_sb_api_key". background.js reads this same key.
 * ============================================================================= */
(function () {
  "use strict";

  const STORAGE_KEY = "webshield_sb_api_key";

  const input   = document.getElementById("apiKey");
  const status  = document.getElementById("status");
  const saveBtn = document.getElementById("saveBtn");
  const clearBtn = document.getElementById("clearBtn");

  function showStatus(text, ok) {
    status.textContent = text;
    status.className = "status " + (ok ? "ok" : "err");
    setTimeout(() => { status.textContent = ""; }, 2500);
  }

  // Load any previously saved key.
  chrome.storage.local.get([STORAGE_KEY], (res) => {
    if (res && res[STORAGE_KEY]) input.value = res[STORAGE_KEY];
  });

  saveBtn.addEventListener("click", () => {
    const key = input.value.trim();
    if (!key) {
      showStatus("Enter a key first", false);
      return;
    }
    chrome.storage.local.set({ [STORAGE_KEY]: key }, () => {
      showStatus("Saved ✓", true);
    });
  });

  clearBtn.addEventListener("click", () => {
    input.value = "";
    chrome.storage.local.remove([STORAGE_KEY], () => {
      showStatus("Cleared", true);
    });
  });
})();
